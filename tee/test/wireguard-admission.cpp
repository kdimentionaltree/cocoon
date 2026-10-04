#include "WireGuardAdmission.h"
#include "tee/cocoon/AttestationCache.h"
#include "tee/cocoon/ProxyConfig.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/tdx/tdx.h"

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iostream>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>

namespace wg = cocoon::wireguard;
using Json = nlohmann::json;

namespace {

unsigned assertions = 0;
void check(bool condition, const char *message) {
  ++assertions;
  if (!condition) throw std::runtime_error(message);
}
template <class F> void rejected(F &&function) {
  ++assertions;
  try { function(); } catch (const wg::Error &) { return; }
  throw std::runtime_error("Invalid admission input was accepted");
}

struct TemporaryDirectory {
  std::string path;
  TemporaryDirectory() {
    std::array<char, 64> name{};
    std::string pattern = "/tmp/cocoon-admission-test-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    auto directory = mkdtemp(name.data());
    if (!directory) throw std::runtime_error("Cannot create test directory");
    path = directory;
  }
  ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
};

void integer(std::string &out, std::uint64_t value, unsigned width) {
  for (unsigned i = width; i > 0; --i) out += static_cast<char>(value >> (8 * (i - 1)));
}
std::string fixture_quote(std::string_view reportdata, std::string image = std::string(64, 'a'),
                          std::uint64_t attributes = 0, bool service = false) {
  std::string out = "TEST" + image + std::string(reportdata);
  integer(out, attributes, 8);
  out += static_cast<char>(service);
  return out;
}

// These synthetic reports exist only in this test executable. The production CLI has no fake provider option.
class FixtureEvidence final : public wg::EvidenceProvider {
 public:
  bool corrupt_report = false;
  bool wrong_image = false;
  std::string replay;
  std::string generated;
  std::chrono::milliseconds delay{0};
  std::string quote(std::string_view reportdata, const wg::Deadline &deadline) override {
    deadline.check();
    if (!replay.empty()) return replay;
    auto resume = wg::Deadline::Clock::now() + delay;
    while (wg::Deadline::Clock::now() < resume) deadline.wait(-1, 0);
    std::string data(reportdata);
    if (corrupt_report) data[0] ^= 1;
    generated = fixture_quote(data, std::string(64, wrong_image ? 'b' : 'a'));
    return generated;
  }
  wg::Evidence verify(std::string_view quote, const wg::Deadline &deadline) override {
    deadline.check();
    if (quote.size() != 141 || quote.substr(0, 4) != "TEST") throw wg::Error("Not a test quote");
    wg::Evidence result{std::string(quote.substr(68, 64)), std::string(quote.substr(4, 64)), 0, quote[140] != 0};
    for (unsigned i = 132; i < 140; ++i) {
      result.td_attributes = (result.td_attributes << 8) | static_cast<unsigned char>(quote[i]);
    }
    return result;
  }
};

class FixtureTee final : public cocoon::TeeInterface {
 public:
  enum class Mode { Normal, Duplicate, Sev, BadClaims };
  explicit FixtureTee(Mode mode = Mode::Normal) : mode_(mode) {}
  td::Status prepare_cert_config(cocoon::TeeCertConfig &config,
                                 const tde2e_core::PublicKey &public_key) const override {
    auto claims = public_key.to_secure_string().as_slice().str();
    if (mode_ == Mode::BadClaims) claims[0] ^= 1;
    config.extra_extensions.emplace_back("1.3.6.1.4.1.12345.1",
                                          fixture_quote(cocoon::hash_public_key(public_key).as_slice().str()));
    config.extra_extensions.emplace_back("1.3.6.1.4.1.12345.2", claims);
    if (mode_ == Mode::Duplicate) config.extra_extensions.push_back(config.extra_extensions.front());
    if (mode_ == Mode::Sev) config.extra_extensions.emplace_back("1.3.6.1.4.1.12345.100", "unexpected");
    return td::Status::OK();
  }
  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512 &) const override {
    return td::Status::Error("Fixture has no hardware reports");
  }
 private:
  Mode mode_;
};

class CountingVerifier final : public cocoon::RATLSInterface {
 public:
  mutable unsigned calls = 0;
  td::Result<tdx::RATLSAttestationReport> attest(const td::UInt512 &claims,
                                                const tdx::RATLSExtensions &) const override {
    ++calls;
    tdx::RATLSAttestationReport report{};
    report.reportdata = claims;
    return report;
  }
  td::Result<sev::RATLSAttestationReport> attest(const td::UInt512 &,
                                                const sev::RATLSExtensions &) const override {
    return td::Status::Error("Only TDX fixtures supported");
  }
};

std::string signing_key() {
  std::string seed(32, 'x');
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                   reinterpret_cast<const unsigned char *>(seed.data()), seed.size()), EVP_PKEY_free);
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  check(key && bio && PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
        "Cannot generate fixture signer");
  char *data = nullptr;
  auto size = BIO_get_mem_data(bio.get(), &data);
  return {data, static_cast<std::size_t>(size)};
}

struct Fixture {
  TemporaryDirectory directory;
  wg::Config a, b;
  wg::Identity identity_a, identity_b;
  wg::Membership membership;
  std::string signer = signing_key();
  std::string envelope;
  Fixture() {
    a.interface = "wg0"; a.overlay_network = "10.77.0.0/24"; a.cluster_id = "cluster";
    a.workload_policy_sha256 = std::string(64, '1'); a.generation = 1;
    a.node_id = "a"; a.node_rank = 0; a.overlay_ipv4 = "10.77.0.1"; a.listen_port = 51820; a.admission_port = 51821;
    a.allowed_image_hashes_hex = {std::string(64, 'a')};
    a.cert_base_name = directory.path + "/a";
    a.peers = {{"b", 1, "10.77.0.2", "198.51.100.2", 51820, 51821, true}};
    b = a; b.node_id = "b"; b.node_rank = 1; b.overlay_ipv4 = "10.77.0.2";
    b.cert_base_name = directory.path + "/b";
    b.peers = {{"a", 0, "10.77.0.1", "198.51.100.1", 51820, 51821, true}};
    wg::Membership placeholder{"cluster", std::string(64, '1'), 1, 1, 2,
      {{"a", 0, std::string(64, '2'), "10.77.0.1", "hSDwCYkwp1R0i33LQ+91oNvzoNJjga9Ou6SpjqmbTmo=",
        std::string(64, 'a')},
       {"b", 1, std::string(64, '3'), "10.77.0.2", "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=",
        std::string(64, 'a')}}};
    auto signed_placeholder = Json::parse(wg::sign_membership(placeholder, signer));
    a.membership_signer_public_key_b64 = b.membership_signer_public_key_b64 =
        signed_placeholder.at("signer_public_key_b64");
    identity_a = wg::load_or_create_identity(a, directory.path + "/state-a");
    identity_b = wg::load_or_create_identity(b, directory.path + "/state-b");
    auto now = static_cast<std::uint64_t>(std::time(nullptr));
    membership = {"cluster", std::string(64, '1'), 1, now - 5, now + 120,
      {{"a", 0, identity_a.boot_id, "10.77.0.1", identity_a.wireguard_public_key_b64, std::string(64, 'a')},
       {"b", 1, identity_b.boot_id, "10.77.0.2", identity_b.wireguard_public_key_b64, std::string(64, 'a')}}};
    envelope = wg::sign_membership(membership, signer);
    certificate(a); certificate(b);
  }
  void certificate(const wg::Config &config, bool attested = true, FixtureTee::Mode mode = FixtureTee::Mode::Normal) {
    FixtureTee tee(mode);
    auto cert = cocoon::generate_cert_and_key(attested ? &tee : nullptr).move_as_ok();
    for (const auto &suffix : {"_cert.pem", "_key.pem"}) std::filesystem::remove(config.cert_base_name + suffix);
    wg::write_public_file(config.cert_base_name + "_cert.pem", cert.cert_pem());
    wg::write_public_file(config.cert_base_name + "_key.pem", cert.key_pem());
    chmod((config.cert_base_name + "_key.pem").c_str(), 0600);
  }
};

void policy_tests() {
  auto verifier = std::make_shared<CountingVerifier>();
  auto key = tde2e_core::PrivateKey::generate().move_as_ok().to_public_key();
  auto policy = cocoon::RATLSPolicy::make(verifier);
  check(policy->validate(key).is_error(), "Verifier accepted absent evidence with empty allowlists");
  check(cocoon::RATLSPolicy::make(nullptr)->validate(key).is_ok(), "Explicit any policy changed");
  check(cocoon::RATLSInterface::add_cache(verifier, nullptr).is_error(), "Null shared cache accepted");
  auto cache = cocoon::AttestationCache::create({.max_entries = 10});
  check(cocoon::RATLSInterface::add_cache(nullptr, cache).is_error(), "Null cached verifier accepted");
  auto first = cocoon::RATLSInterface::add_cache(verifier, cache).move_as_ok();
  auto second = cocoon::RATLSInterface::add_cache(verifier, cache).move_as_ok();
  tdx::RATLSExtensions extensions{"fixture", "claims"};
  auto hash = cocoon::hash_public_key(key);
  check(first->attest(hash, extensions).is_ok() && second->attest(hash, extensions).is_ok() && verifier->calls == 1,
        "Two verifiers did not retain shared cache ownership");
  cocoon::ProxyConfig config;
  config.policies.push_back({"cluster_peer", "unknown", "", {}});
  check(cocoon::validate_proxy_config(config).is_error(), "Unknown router policy was not rejected");
}

void transcript_tests(Fixture &fixture) {
  auto m = fixture.membership;
  auto make_record = [&](const wg::Membership &input, std::string n = std::string(32, 'c'),
                         std::string tls = std::string(32, 'e'), std::string channel = std::string(32, 'g')) {
    return wg::admission_record(input, "a", "b", n, std::string(32, 'd'), tls, std::string(32, 'f'), channel);
  };
  auto record = make_record(m);
  auto data = wg::admission_reportdata(record, false);
  check(data.size() == 64 && data != wg::admission_reportdata(record, true), "Quote reflection was possible");
  for (auto edit : std::vector<std::function<void(wg::Membership &)>>{
      [](auto &v) { v.cluster_id += "x"; }, [](auto &v) { v.workload_policy_sha256[0] = '2'; },
      [](auto &v) { ++v.generation; }, [](auto &v) { ++v.expires_at; },
      [](auto &v) { v.members[0].boot_id[0] = v.members[0].boot_id[0] == '0' ? '1' : '0'; },
      [](auto &v) { v.members[0].overlay_ipv4 = "10.77.0.3"; },
      [](auto &v) { std::swap(v.members[0].wireguard_public_key_b64, v.members[1].wireguard_public_key_b64); },
      [](auto &v) { std::swap(v.members[0].node_rank, v.members[1].node_rank); }}) {
    auto changed = m; edit(changed);
    check(wg::admission_reportdata(make_record(changed), false) != data, "Membership field was not quote-bound");
  }
  check(wg::admission_reportdata(make_record(m, std::string(32, 'x')), false) != data, "Fresh nonce was not bound");
  check(wg::admission_reportdata(make_record(m, std::string(32, 'c'), std::string(32, 'x')), false) != data,
        "TLS identity was not bound");
  check(wg::admission_reportdata(make_record(m, std::string(32, 'c'), std::string(32, 'e'),
                                            std::string(32, 'x')), false) != data,
        "Live TLS connection was not bound");
  wg::Evidence evidence{data, std::string(64, 'a'), 1ULL << 28, false};
  wg::check_evidence(evidence, data, std::string(64, 'a'));
  rejected([&] {
    wg::check_evidence(evidence, wg::admission_reportdata(make_record(m, std::string(32, 'x')), false),
                       evidence.image_hash_hex);
  });
  rejected([&] { wg::check_evidence(evidence, data, std::string(64, 'b')); });
  for (auto bit : {0, 29, 63, 40}) {
    auto bad = evidence; bad.td_attributes |= 1ULL << bit;
    rejected([&] { wg::check_evidence(bad, data, evidence.image_hash_hex); });
  }
  evidence.has_service_td = true;
  rejected([&] { wg::check_evidence(evidence, data, evidence.image_hash_hex); });
  rejected([&] { wg::admission_record(m, "a", "b", std::string(31, 'c'), std::string(32, 'd'),
                                     std::string(32, 'e'), std::string(32, 'f'), std::string(32, 'g')); });
}

std::string paired_session(Fixture &fixture, bool success, bool corrupt = false, bool wrong_image = false,
                            std::string replay = {}, std::chrono::milliseconds delay = {}) {
  int sockets[2];
  check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0, "Cannot create session pair");
  std::cout.flush();
  auto child = fork();
  check(child >= 0, "Cannot start test peer");
  if (child == 0) {
    close(sockets[0]);
    FixtureEvidence provider;
    bool admitted = false;
    try {
      auto output = wg::admit_connected_socket(sockets[1], true, fixture.b, fixture.identity_b, fixture.envelope,
                                                "a", provider,
                                                wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3)));
      admitted = Json::parse(output).at("status") == "peer_admitted";
    } catch (const wg::Error &) {}
    close(sockets[1]);
    _exit(admitted == success ? 0 : 1);
  }
  close(sockets[1]);
  FixtureEvidence provider;
  provider.corrupt_report = corrupt; provider.wrong_image = wrong_image;
  provider.replay = std::move(replay);
  provider.delay = delay;
  bool admitted = false;
  try {
    auto output = wg::admit_connected_socket(sockets[0], false, fixture.a, fixture.identity_a, fixture.envelope,
                                              "b", provider,
                                              wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3)));
    auto status = Json::parse(output);
    admitted = status.at("status") == "peer_admitted";
    check(status.at("peer_wireguard_public_key_b64") == fixture.identity_b.wireguard_public_key_b64 &&
              status.at("workload_ready") == false, "Admission exposed an incorrect peer or workload readiness");
  } catch (const wg::Error &error) {
    if (success) std::cerr << "Unexpected admission failure: " << error.what() << '\n';
  }
  close(sockets[0]);
  int result = 0;
  check(waitpid(child, &result, 0) == child && WIFEXITED(result) && WEXITSTATUS(result) == 0,
        "Test peer had an unexpected admission result");
  check(admitted == success, "Local peer had an unexpected admission result");
  return provider.generated;
}

void quote_parser_tests() {
  auto put_le = [](std::string &out, std::size_t offset, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) out[offset + i] = static_cast<char>(value >> (8 * i));
  };
  std::string v4(48 + 584 + 4 + 1, '\0');
  put_le(v4, 0, 4, 2); put_le(v4, 2, 2, 2); put_le(v4, 4, 0x81, 4);
  put_le(v4, 48 + 120, 1ULL << 28, 8); put_le(v4, 48 + 584, 1, 4);
  auto parsed = tdx::tdx_parse_quote({v4});
  check(parsed.is_ok() && parsed.ok().td_attributes == (1ULL << 28) && !parsed.ok().has_service_td,
        "Valid TDX v4 structure did not parse");
  for (std::size_t i = 0; i < v4.size(); ++i) {
    check(tdx::tdx_parse_quote({v4.substr(0, i)}).is_error(), "Truncated TDX quote accepted");
  }
  check(tdx::tdx_parse_quote({v4 + "x"}).is_error(), "Trailing TDX signature bytes accepted");
  auto sgx = v4; put_le(sgx, 4, 0, 4);
  check(tdx::tdx_parse_quote({sgx}).is_error(), "Wrong-platform quote accepted");
  auto v5 = v4.substr(0, 48) + std::string(6, '\0') + v4.substr(48);
  put_le(v5, 0, 5, 2); put_le(v5, 48, 2, 2); put_le(v5, 50, 584, 4);
  check(tdx::tdx_parse_quote({v5}).is_ok(), "Valid TDX v5 structure rejected");
  auto bad = v5; put_le(bad, 50, 0xffffffff, 4);
  check(tdx::tdx_parse_quote({bad}).is_error(), "Oversized v5 body accepted");
  bad = v5; put_le(bad, 48, 1, 2);
  check(tdx::tdx_parse_quote({bad}).is_error(), "SGX v5 body accepted as TDX");
  auto v15 = v5.substr(0, 54 + 584) + std::string(64, '\0') + v5.substr(54 + 584);
  put_le(v15, 48, 3, 2); put_le(v15, 50, 648, 4);
  check(tdx::tdx_parse_quote({v15}).is_ok(), "TDX 1.5 structure rejected");
  v15[54 + 584 + 16] = 1;
  check(tdx::tdx_parse_quote({v15}).ok().has_service_td, "Service-TD measurement was omitted");
  // Structural fixtures have no signature and must never pass DCAP.
  check(tdx::tdx_verify_quote({v4}).is_error(), "Synthetic quote passed hardware verification");
}

void deadline_tests(Fixture &fixture) {
  int sockets[2];
  check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0, "Cannot create timeout pair");
  FixtureEvidence provider;
  auto start = wg::Deadline::Clock::now();
  rejected([&] { wg::admit_connected_socket(sockets[0], false, fixture.a, fixture.identity_a, fixture.envelope,
                                           "b", provider, wg::Deadline(start + std::chrono::milliseconds(150))); });
  check(wg::Deadline::Clock::now() - start < std::chrono::seconds(1), "Silent peer exceeded deadline");
  unsigned checks = 0;
  rejected([&] { wg::admit_connected_socket(sockets[0], false, fixture.a, fixture.identity_a, fixture.envelope,
                                           "b", provider,
                                           wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3),
                                                                         [&] { return ++checks > 4; })); });
  close(sockets[0]); close(sockets[1]);
}

void malformed_frame_tests(Fixture &fixture) {
  auto frame = [](unsigned char type, std::string_view body) {
    std::string output;
    integer(output, body.size() + 1, 4);
    output += static_cast<char>(type);
    output += body;
    return output;
  };
  auto wrong_peer = std::string("CWGA1", 6) + std::string("\0\1", 2) + "x" + std::string(64, 'z');
  auto wrong_digest = std::string("CWGA1", 6) + std::string("\0\1", 2) + "b" + std::string(64, 'z');
  for (const auto &invalid : {std::string(4, '\xff'), std::string(4, '\0'), frame(1, "bad"), frame(2, "wrong-type"),
                              std::string("\0\0\0\x89", 4), frame(1, wrong_peer), frame(1, wrong_digest)}) {
    int sockets[2];
    check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0,
          "Cannot create malformed-frame pair");
    std::cout.flush();
    auto child = fork();
    check(child >= 0, "Cannot start malformed-frame peer");
    if (child == 0) {
      close(sockets[0]);
      bool established = false;
      try {
        // This isolated adversarial fixture uses TLS possession only; the tested participant verifies its quote.
        cocoon::SslOptions options;
        options.mode = cocoon::SslOptions::Mode::Server;
        options.cert_and_key = cocoon::load_cert_and_key(fixture.b.cert_base_name).move_as_ok();
        options.custom_verify = [](int, void *) { return 1; };
        auto context = cocoon::create_ssl_ctx(std::move(options)).move_as_ok();
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(static_cast<SSL_CTX *>(context.get())), SSL_free);
        check(ssl && SSL_set_fd(ssl.get(), sockets[1]) == 1, "Cannot create adversarial TLS session");
        SSL_set_accept_state(ssl.get());
        wg::Deadline deadline(wg::Deadline::Clock::now() + std::chrono::seconds(2));
        auto retry = [&](int result) {
          auto error = SSL_get_error(ssl.get(), result);
          if (error == SSL_ERROR_WANT_READ) deadline.wait(sockets[1], POLLIN);
          else if (error == SSL_ERROR_WANT_WRITE) deadline.wait(sockets[1], POLLOUT);
          else throw wg::Error("Test connection closed");
        };
        for (;;) {
          deadline.check(); ERR_clear_error();
          auto result = SSL_do_handshake(ssl.get());
          if (result == 1) break;
          retry(result);
        }
        established = true;
        auto receive = [&](char *data, std::size_t size) {
          while (size) {
            deadline.check(); ERR_clear_error();
            std::size_t received = 0;
            auto result = SSL_read_ex(ssl.get(), data, size, &received);
            if (result == 1) { data += received; size -= received; }
            else retry(result);
          }
        };
        std::array<char, 4> header{};
        receive(header.data(), header.size());
        std::size_t size = 0;
        for (unsigned char byte : header) size = (size << 8) | byte;
        check(size <= 137, "Invalid client fixture hello length");
        std::string client_hello(size, '\0');
        receive(client_hello.data(), client_hello.size());
        // A single TLS application write gives the participant a malformed/truncated frame, then EOF.
        for (;;) {
          deadline.check(); ERR_clear_error();
          std::size_t written = 0;
          auto result = SSL_write_ex(ssl.get(), invalid.data(), invalid.size(), &written);
          if (result == 1) break;
          retry(result);
        }
      } catch (const std::exception &) {}
      close(sockets[1]);
      _exit(established ? 0 : 1);
    }
    close(sockets[1]);
    FixtureEvidence provider;
    bool rejected_frame = false;
    try {
      wg::admit_connected_socket(sockets[0], false, fixture.a, fixture.identity_a, fixture.envelope,
                                  "b", provider, wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(2)));
    } catch (const wg::Error &error) {
      auto reason = std::string(error.what());
      rejected_frame = reason.find("frame size") != std::string::npos || reason.find("hello") != std::string::npos ||
                       reason.find("Unexpected admission message") != std::string::npos ||
                       reason.find("Unexpected admission peer identity") != std::string::npos ||
                       reason.find("membership digest") != std::string::npos ||
                       (invalid.size() == 4 && static_cast<unsigned char>(invalid.back()) == 137 &&
                        reason.find("connection failed") != std::string::npos);
    }
    check(rejected_frame, "Malformed frame failed for an unexpected reason");
    close(sockets[0]);
    int result = 0;
    check(waitpid(child, &result, 0) == child && WIFEXITED(result) && WEXITSTATUS(result) == 0,
          "Malformed-frame fixture did not establish TLS");
  }
}

void worker_tests() {
  auto deadline = [] { return wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(2)); };
  check(wg::run_evidence_worker("quote", std::string(64, 'o'), deadline()) == "response",
        "Evidence worker did not complete");
  rejected([&] { wg::run_evidence_worker("quote", std::string(64, 'f'), deadline()); });
  rejected([&] { wg::run_evidence_worker("quote", std::string(64, 'l'), deadline()); });
  rejected([&] { wg::run_evidence_worker("invalid", "input", deadline()); });
  auto start = wg::Deadline::Clock::now();
  rejected([&] { wg::run_evidence_worker("quote", std::string(64, 's'),
                                        wg::Deadline(start + std::chrono::milliseconds(150))); });
  check(wg::Deadline::Clock::now() - start < std::chrono::seconds(1), "Blocking verifier exceeded deadline");
  unsigned checks = 0;
  rejected([&] { wg::run_evidence_worker("quote", std::string(64, 's'),
                                        wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(2),
                                                      [&] { return ++checks > 5; })); });
  check(waitpid(-1, nullptr, WNOHANG) < 0 && errno == ECHILD, "Cancelled verifier was left detached or unreaped");
  if (!wg::admission_supported()) rejected([&] { wg::real_evidence_provider(); });
}

}  // namespace

int main(int argc, char **argv) {
  std::signal(SIGPIPE, SIG_IGN);
  SET_VERBOSITY_LEVEL(0);
  if (argc == 2 && std::string_view(argv[1]) == "--internal-quote") {
    // Exercise the real exec/pipe/kill/reap implementation using a child local to this test executable.
    std::string request;
    std::array<char, 128> buffer{};
    for (;;) {
      auto size = read(STDIN_FILENO, buffer.data(), buffer.size());
      if (size <= 0) break;
      request.append(buffer.data(), static_cast<std::size_t>(size));
    }
    if (request.size() != 64) return 1;
    if (request.front() == 'f') return 1;
    if (request.front() == 's') for (;;) pause();
    if (request.front() == 'l') std::cout << std::string(32769, 'x');
    else std::cout << "response";
    return 0;
  }
  try {
    worker_tests(); policy_tests(); quote_parser_tests();
    Fixture fixture;
    transcript_tests(fixture);
    auto old_quote = paired_session(fixture, true);
    check(!old_quote.empty(), "No fresh test quote generated");
    paired_session(fixture, false, false, false, old_quote);
    paired_session(fixture, false, true);
    paired_session(fixture, false, false, true);
    deadline_tests(fixture);
    malformed_frame_tests(fixture);
    fixture.certificate(fixture.b, false);
    paired_session(fixture, false);
    for (auto mode : {FixtureTee::Mode::Duplicate, FixtureTee::Mode::Sev, FixtureTee::Mode::BadClaims}) {
      fixture.certificate(fixture.b, true, mode);
      paired_session(fixture, false);
    }
    fixture.certificate(fixture.b);
    auto short_lease = fixture.membership;
    short_lease.expires_at = static_cast<std::uint64_t>(std::time(nullptr)) + 1;
    fixture.envelope = wg::sign_membership(short_lease, fixture.signer);
    paired_session(fixture, false, false, false, {}, std::chrono::milliseconds(1200));
    auto expired = fixture.membership;
    expired.not_before = 1; expired.expires_at = 2;
    fixture.envelope = wg::sign_membership(expired, fixture.signer);
    paired_session(fixture, false);
    std::cout << "WireGuard admission: " << assertions << " assertions passed (synthetic evidence only)\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "WireGuard admission test: " << error.what() << '\n';
    return 1;
  }
}
