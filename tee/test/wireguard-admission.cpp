#include "WireGuardAdmission.h"
#include "WireGuardDevice.h"
#include "WireGuardSupervisor.h"
#include "tee/cocoon/AttestationCache.h"
#include "tee/cocoon/ProxyConfig.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/tdx/tdx.h"
#include "tee/cocoon/tdx/Tee.h"
#include "tee/cocoon/sev/Tee.h"

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iostream>

#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/un.h>
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
  std::unique_ptr<wg::EvidenceProvider> fake;
  std::string quote(std::string_view reportdata, const wg::Deadline &deadline) override {
    deadline.check();
    if (!replay.empty()) return replay;
    auto resume = wg::Deadline::Clock::now() + delay;
    while (wg::Deadline::Clock::now() < resume) deadline.wait(-1, 0);
    std::string data(reportdata);
    if (corrupt_report) data[0] ^= 1;
    generated = fake ? fake->quote(data, deadline) : fixture_quote(data, std::string(64, wrong_image ? 'b' : 'a'));
    if (fake && wrong_image) generated[0] ^= 1;
    return generated;
  }
  wg::Evidence verify(std::string_view quote, const wg::Deadline &deadline) override {
    deadline.check();
    if (fake) return fake->verify(quote, deadline);
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
                            std::string replay = {}, std::chrono::milliseconds delay = {},
                            const wg::AfterAdmission &client_setup = {}, const wg::AfterAdmission &server_setup = {}) {
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
      if (fixture.b.fake_tee) provider.fake = wg::evidence_provider(fixture.b);
      auto output = wg::admit_connected_socket(sockets[1], true, fixture.b, fixture.identity_b, fixture.envelope,
                                                "a", provider,
                                                wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3)), server_setup);
      admitted = Json::parse(output).at("status") == "peer_admitted";
    } catch (const wg::Error &) {}
    close(sockets[1]);
    _exit(admitted == success ? 0 : 1);
  }
  close(sockets[1]);
  FixtureEvidence provider;
  if (fixture.a.fake_tee) provider.fake = wg::evidence_provider(fixture.a);
  provider.corrupt_report = corrupt; provider.wrong_image = wrong_image;
  provider.replay = std::move(replay);
  provider.delay = delay;
  bool admitted = false;
  try {
    auto output = wg::admit_connected_socket(sockets[0], false, fixture.a, fixture.identity_a, fixture.envelope,
                                              "b", provider,
                                              wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3)), client_setup);
    auto status = Json::parse(output);
    admitted = status.at("status") == "peer_admitted";
    check(status.at("peer_wireguard_public_key_b64") == fixture.identity_b.wireguard_public_key_b64 &&
              status.at("workload_ready") == false, "Admission exposed an incorrect peer or workload readiness");
    check(status.at("attestation_type") == (fixture.a.fake_tee ? "fake_tee" : "tdx"),
          "Admission omitted its evidence mode");
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

void fake_tee_tests() {
  for (unsigned combination = 0; combination < 3; ++combination) {
    Fixture fixture;
    fixture.a.fake_tee = fixture.b.fake_tee = fixture.membership.fake_tee = true;
    fixture.a.image_policy = fixture.b.image_policy = wg::ImagePolicy::SignedMembership;
    fixture.a.allowed_image_hashes_hex.clear(); fixture.b.allowed_image_hashes_hex.clear();
    fixture.identity_a = wg::load_or_create_identity(fixture.a, fixture.directory.path + "/fake-a");
    fixture.identity_b = wg::load_or_create_identity(fixture.b, fixture.directory.path + "/fake-b");
    for (unsigned i = 0; i < 2; ++i) {
      auto &config = i == 0 ? fixture.a : fixture.b;
      const auto &identity = i == 0 ? fixture.identity_a : fixture.identity_b;
      auto tee = (combination == 1 || (combination == 2 && i == 1))
          ? sev::make_tee(true, {}).move_as_ok() : tdx::make_tee(true, {}).move_as_ok();
      auto cert = cocoon::generate_cert_and_key(tee.get()).move_as_ok();
      for (const auto &suffix : {"_cert.pem", "_key.pem"}) std::filesystem::remove(config.cert_base_name + suffix);
      wg::write_public_file(config.cert_base_name + "_cert.pem", cert.cert_pem());
      wg::write_public_file(config.cert_base_name + "_key.pem", cert.key_pem());
      chmod((config.cert_base_name + "_key.pem").c_str(), 0600);
      auto &member = fixture.membership.members[i];
      member.boot_id = identity.boot_id; member.wireguard_public_key_b64 = identity.wireguard_public_key_b64;
      member.image_hash_hex = td::hex_encode(tee->make_report(td::UInt512{}).move_as_ok().image_hash().as_slice());
      auto provider = wg::evidence_provider(config);
      auto deadline = wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(3));
      auto quote = provider->quote(std::string(64, 'q'), deadline);
      auto evidence = provider->verify(quote, deadline);
      wg::check_evidence(evidence, std::string(64, 'q'), member.image_hash_hex);
      rejected([&] { provider->verify(quote + "trailing", deadline); });
      rejected([&] { provider->verify(std::string_view(quote).substr(1), deadline); });
      rejected([&] { provider->quote("short", deadline); });
      check(wg::admission_supported(config), "SDK-free fake admission unavailable");
    }
    fixture.envelope = wg::sign_membership(fixture.membership, fixture.signer);
    auto quote = paired_session(fixture, true);
    paired_session(fixture, false, true); // Fresh synthetic REPORTDATA still binds the challenge.
    paired_session(fixture, false, false, true);
    paired_session(fixture, false, false, false, quote);
    paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
      auto now = wg::Deadline::Clock::now();
      auto wall = static_cast<std::uint64_t>(std::time(nullptr));
      wg::LeaseSupervisor supervisor(fixture.a, session.membership(), now, wall);
      supervisor.authorize(session, now, wall);
      check(Json::parse(supervisor.status("starting", false, now, wall))["attestation_type"] == "fake_tee",
            "Supervisor claimed real evidence for fake admission");
    });
    auto real = fixture.a; real.fake_tee = false;
    rejected([&] { wg::verify_membership(real, fixture.identity_a, fixture.envelope, std::time(nullptr)); });
  }
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

class FakeNetworkCommands final : public wg::NetworkCommands {
 public:
  struct Call { wg::NetworkTool tool; std::vector<std::string> arguments; std::string input; int key_fd; };
  std::vector<Call> calls;
  Json links = Json::array({{{"ifname", "eth0"}}});
  Json addresses = Json::array({{{"ifname", "eth0"}, {"addr_info", Json::array({{{"local", "192.0.2.1"}, {"prefixlen", 24}}})}}});
  Json routes = Json::array({{{"dst", "192.0.2.0/24"}, {"dev", "eth0"}}});
  Json firewall = Json::array();
  std::map<std::string, std::string> kernel_peers;
  std::string public_key;
  unsigned mutations = 0, fail_mutation = 0;
  bool fail_after_effect = false;

  std::string run(wg::NetworkTool tool, const std::vector<std::string> &args, std::string_view input,
                  int key_fd, const wg::Deadline &deadline) override {
    deadline.check();
    calls.push_back({tool, args, std::string(input), key_fd});
    auto has = [&](std::string_view word) { return std::find(args.begin(), args.end(), word) != args.end(); };
    bool mutation = !has("show") && !has("get") && !has("list");
    if (mutation) {
      ++mutations;
      if (mutations == fail_mutation && !fail_after_effect) throw wg::Error("Injected command failure");
    }
    std::string output;
    if (tool == wg::NetworkTool::Ip && args == std::vector<std::string>{"-j", "link", "show"}) output = links.dump();
    else if (tool == wg::NetworkTool::Ip && has("address") && has("show")) output = addresses.dump();
    else if (tool == wg::NetworkTool::Ip && has("route") && has("show")) output = routes.dump();
    else if (tool == wg::NetworkTool::Ip && has("route") && has("get")) output = "[{\"dev\":\"eth0\"}]";
    else if (tool == wg::NetworkTool::Nftables && has("tables")) {
      output = Json{{"nftables", firewall.empty() ? Json::array() : Json::array({firewall[0]})}}.dump();
    } else if (tool == wg::NetworkTool::Nftables && has("table")) output = Json{{"nftables", firewall}}.dump();
    else if (tool == wg::NetworkTool::Nftables) {
      auto request = Json::parse(input);
      for (const auto &command : request["nftables"]) {
        auto operation = command.begin().key();
        const auto &object = command.begin().value();
        if (object.contains("element") || operation == "flush") {
          const auto &body = object.begin().value();
          auto found = std::find_if(firewall.begin(), firewall.end(), [&](const Json &entry) {
            return entry.contains("set") && entry["set"].at("name") == body.at("name");
          });
          if (found == firewall.end()) throw wg::Error("Test firewall set is absent");
          if (operation == "flush") (*found)["set"].erase("elem");
          else {
            auto &elements = (*found)["set"]["elem"];
            if (elements.is_null()) elements = Json::array();
            for (const auto &element : body.at("elem")) elements.push_back(element);
          }
        } else if (operation == "delete") firewall.clear();
        else firewall.push_back(object);
      }
    } else if (tool == wg::NetworkTool::Ip && has("link") && has("add")) {
      auto alias = std::find(args.begin(), args.end(), "alias");
      links.push_back({{"ifname", args[3]}, {"ifalias", *(alias + 1)}, {"mtu", 1420}, {"flags", Json::array()}});
    } else if (tool == wg::NetworkTool::Ip && has("link") && has("delete")) {
      links.erase(std::remove_if(links.begin(), links.end(), [&](const Json &link) { return link.at("ifname") == args[3]; }), links.end());
      kernel_peers.clear();
    } else if (tool == wg::NetworkTool::Ip && has("link") && has("mtu")) {
      links.back()["mtu"] = std::stoul(*(std::find(args.begin(), args.end(), "mtu") + 1));
      links.back()["flags"] = Json::array({"UP"});
    } else if (tool == wg::NetworkTool::WireGuard && has("peer") && has("set")) {
      auto key = *(std::find(args.begin(), args.end(), "peer") + 1);
      if (has("remove")) kernel_peers.erase(key);
      else kernel_peers[key] = *(std::find(args.begin(), args.end(), "allowed-ips") + 1);
    } else if (tool == wg::NetworkTool::WireGuard && has("allowed-ips")) {
      for (const auto &[key, ips] : kernel_peers) output += key + "\t" + ips + "\n";
    } else if (tool == wg::NetworkTool::WireGuard && has("public-key")) output = public_key + "\n";
    if (mutation && mutations == fail_mutation && fail_after_effect) throw wg::Error("Injected uncertain command completion");
    return output;
  }
};

wg::Deadline device_deadline() { return wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(2)); }

void device_tests(Fixture &fixture) {
  auto real = wg::real_network_commands();
  // Validation and cancellation must happen before any helper is launched.
  rejected([&] { real->run(wg::NetworkTool::Ip, {std::string("x\0y", 3)}, {}, -1, device_deadline()); });
  rejected([&] { real->run(wg::NetworkTool::Nftables, {}, std::string(1024 * 1024 + 1, 'x'), -1, device_deadline()); });
  rejected([&] { real->run(wg::NetworkTool::Nftables, {}, {}, 0, device_deadline()); });
  rejected([&] { real->run(wg::NetworkTool::Ip, {"-j", "link", "show"}, {}, -1,
      wg::Deadline(wg::Deadline::Clock::now() + std::chrono::seconds(1), [] { return true; })); });
  if (access("/usr/sbin/ip", X_OK) == 0) {
    check(Json::parse(real->run(wg::NetworkTool::Ip, {"-j", "link", "show"}, {}, -1, device_deadline())).is_array(),
          "Real helper did not return bounded link inventory");
    rejected([&] { real->run(wg::NetworkTool::Ip, {"--invalid-cocoon-test-option"}, {}, -1, device_deadline()); });
    check(waitpid(-1, nullptr, WNOHANG) < 0 && errno == ECHILD, "Network helper was not reaped");
  }
  {
    wg::RuntimeIdentity identity(fixture.a, fixture.directory.path + "/state-a");
    check(identity.identity().wireguard_public_key_b64 == fixture.identity_a.wireguard_public_key_b64,
          "Runtime identity changed enrolled key");
    check((fcntl(identity.key_fd(), F_GETFD) & FD_CLOEXEC) != 0, "Runtime key is inheritable by unrelated children");
    auto seals = fcntl(identity.key_fd(), F_GET_SEALS);
    check((seals & (F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) ==
              (F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK), "Runtime key is not sealed");
    check(write(identity.key_fd(), "x", 1) < 0, "Runtime key can be overwritten");
    rejected([&] { wg::load_or_create_identity(fixture.a, fixture.directory.path + "/state-a"); });
    // Fail before and after each setup mutation; a created but timed-out link must also be removed.
    for (bool after : {false, true}) {
      for (unsigned step = 1; step <= 5; ++step) {
        FakeNetworkCommands commands;
        commands.public_key = fixture.identity_a.wireguard_public_key_b64;
        commands.fail_mutation = step; commands.fail_after_effect = after;
        wg::WireGuardDevice device(fixture.a, commands);
        rejected([&] { device.start(identity, device_deadline()); });
        check(commands.links.size() == 1, "Failed setup left a WireGuard interface");
        if (step > 1 || after) check(!commands.firewall.empty(), "Failed setup removed the fallback guard");
      }
    }
    FakeNetworkCommands commands;
    commands.public_key = fixture.identity_a.wireguard_public_key_b64;
    wg::WireGuardDevice device(fixture.a, commands);
    device.start(identity, device_deadline());
    check(commands.links.size() == 2 && !commands.firewall.empty(), "Device did not install its guarded interface");
    for (const auto &call : commands.calls) {
      check(std::find(call.arguments.begin(), call.arguments.end(), "peer") == call.arguments.end(),
            "Device installed a peer before live admission");
      if (call.key_fd >= 0) check(call.tool == wg::NetworkTool::WireGuard &&
          call.arguments.back() == "/proc/self/fd/3", "Private key was passed as command text");
    }
    check(commands.firewall.dump().find("forward") != std::string::npos &&
          commands.firewall.dump().find("51822") != std::string::npos, "Gate omitted forwarding or narrow probe rules");
    device.stop(device_deadline());
    check(commands.links.size() == 1 && !commands.firewall.empty(), "Cleanup did not retain an independent closed gate");
    auto previous = commands.mutations;
    device.stop(device_deadline());
    check(commands.mutations == previous, "Cleanup is not idempotent");
    auto inventory = Json::parse(wg::inspect_guard(fixture.a, commands, device_deadline()));
    check(inventory.at("nftables") == commands.firewall, "Read-only gate inspection changed inventory");
    check(commands.mutations == previous, "Gate inspection mutated network state");
    // The exact retained firewall can be reused; a changed guard is never flushed or adopted.
    for (auto &object : commands.firewall) {
      object.begin().value()["handle"] = 42;
      if (object.contains("rule")) {
        auto &expressions = object["rule"]["expr"];
        expressions.erase(std::remove_if(expressions.begin(), expressions.end(), [](const Json &expression) {
          return expression.contains("match") && expression["match"].at("left").contains("meta") &&
              expression["match"]["left"]["meta"]["key"] == "l4proto";
        }), expressions.end());
      }
    }
    wg::inspect_guard(fixture.a, commands, device_deadline());
    check(commands.mutations == previous, "Normalized gate inspection mutated network state");
    device.start(identity, device_deadline());
    device.stop(device_deadline());
    // Reconstruct the exact previous closed gate; upgrade must remain a single transaction.
    auto legacy = commands.firewall;
    legacy.erase(std::remove_if(legacy.begin(), legacy.end(), [](const Json &object) {
      if (object.contains("set")) return true;
      return object.contains("rule") && (object["rule"]["expr"].dump().find("51823") != std::string::npos ||
          object["rule"]["expr"].dump().find("@active_peers") != std::string::npos);
    }), legacy.end());
    commands.firewall = legacy;
    auto upgrade_begin = commands.calls.size();
    device.start(identity, device_deadline());
    bool upgraded_atomically = false;
    for (std::size_t i = upgrade_begin; i < commands.calls.size(); ++i) {
      const auto &call = commands.calls[i];
      if (call.tool == wg::NetworkTool::Nftables && call.input.find("delete") != std::string::npos) {
        upgraded_atomically = call.input.find("active_peers") != std::string::npos && call.input.find("create") != std::string::npos;
      }
    }
    check(upgraded_atomically, "Legacy guard upgrade opened a gap between delete and replacement");
    commands.fail_mutation = commands.mutations + 1;
    rejected([&] { device.stop(device_deadline()); });
    check(commands.links.size() == 1, "Failed gate withdrawal prevented owned interface removal");
    commands.fail_mutation = 0;
    commands.firewall.back()["rule"]["expr"] = Json::array({{{"accept", nullptr}}});
    previous = commands.mutations;
    rejected([&] { wg::inspect_guard(fixture.a, commands, device_deadline()); });
    check(commands.mutations == previous, "Rejected gate inspection mutated network state");
    rejected([&] { device.start(identity, device_deadline()); });
    check(commands.links.size() == 1, "Changed firewall allowed interface creation");
    for (unsigned conflict = 0; conflict < 4; ++conflict) {
      FakeNetworkCommands bad;
      bad.public_key = fixture.identity_a.wireguard_public_key_b64;
      if (conflict == 0) bad.links.push_back({{"ifname", "wg0"}});
      if (conflict == 1) bad.addresses[0]["addr_info"][0]["local"] = "10.77.0.9";
      if (conflict == 2) bad.routes.push_back({{"dst", "10.0.0.0/8"}, {"dev", "eth0"}});
      if (conflict == 3) bad.public_key = fixture.identity_b.wireguard_public_key_b64;
      wg::WireGuardDevice bad_device(fixture.a, bad);
      rejected([&] { bad_device.start(identity, device_deadline()); });
      if (conflict < 3) check(bad.mutations == 0, "Preflight conflict modified existing network state");
      else check(bad.links.size() == 1, "Wrong local key survived setup");
    }
    FakeNetworkCommands owned;
    owned.public_key = fixture.identity_a.wireguard_public_key_b64;
    {
      wg::WireGuardDevice own_device(fixture.a, owned);
      own_device.start(identity, device_deadline());
      owned.links.back()["ifalias"] = "another-owner";
      rejected([&] { own_device.stop(device_deadline()); });
    }
    check(owned.links.size() == 2, "Cleanup deleted an interface with another owner");
  }
  check(wg::load_or_create_identity(fixture.a, fixture.directory.path + "/state-a").boot_id == fixture.identity_a.boot_id,
        "Runtime identity lock survived shutdown");
  for (unsigned fail = 0; fail <= 2; ++fail) {
    wg::RuntimeIdentity identity(fixture.a, fixture.directory.path + "/state-a");
    FakeNetworkCommands commands;
    commands.public_key = fixture.identity_a.wireguard_public_key_b64;
    wg::WireGuardDevice device(fixture.a, commands);
    device.start(identity, device_deadline());
    commands.fail_mutation = fail == 0 ? 0 : commands.mutations + fail;
    paired_session(fixture, fail == 0, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
      device.install_peer(session, device_deadline());
      session.synchronize("device-installed");
      if (fail == 0) {
        device.check_inventory(device_deadline());
        device.install_peer(session, device_deadline());  // Same-key renewal preserves live kernel sessions.
        auto now = wg::Deadline::Clock::now();
        check(device.update_workload({{"b", now + std::chrono::seconds(30)}}, now + std::chrono::seconds(30), device_deadline()),
              "Valid supervised permits did not open the timed gate");
        unsigned populated = 0;
        for (const auto &object : commands.firewall) if (object.contains("set") && object["set"].contains("elem")) {
          ++populated;
          for (const auto &element : object["set"]["elem"]) {
            auto timeout = element["elem"]["timeout"].get<std::int64_t>();
            check(timeout > 0 && timeout <= 28, "Kernel workload timeout exceeds lease/liveness deadline");
          }
        }
        check(populated == 2, "Timed workload gate omitted peer/group permissions");
        auto mutations = commands.mutations;
        check(Json::parse(wg::inspect_guard(fixture.a, commands, device_deadline())).at("nftables") == commands.firewall,
              "Gate inspection did not preserve live permissions");
        check(commands.mutations == mutations, "Live gate inspection withdrew permissions");
        check(!device.update_workload({}, now + std::chrono::seconds(1), device_deadline()), "Nearly expired lease opened kernel gate");
        for (const auto &object : commands.firewall) if (object.contains("set")) {
          check(!object["set"].contains("elem"), "Withdrawal retained kernel workload permissions");
        }
        commands.links.back()["flags"] = Json::array();
        rejected([&] { device.check_inventory(device_deadline()); });
        commands.links.back()["flags"] = Json::array({"UP"});
        commands.kernel_peers[fixture.identity_b.wireguard_public_key_b64] = "0.0.0.0/0";
        rejected([&] { device.check_inventory(device_deadline()); });
        commands.kernel_peers[fixture.identity_b.wireguard_public_key_b64] = "10.77.0.2/32";
      }
    }, [&](const wg::AdmittedSession &session) { session.synchronize("device-installed"); });
    bool peer_installed = false, route_installed = false;
    for (const auto &call : commands.calls) {
      if (call.tool == wg::NetworkTool::WireGuard && call.arguments.size() > 3 && call.arguments[2] == "peer") {
        peer_installed = true;
        check(call.arguments[3] == fixture.identity_b.wireguard_public_key_b64 &&
            std::find(call.arguments.begin(), call.arguments.end(), "10.77.0.2/32") != call.arguments.end(),
            "Device installed the wrong admitted key or broad AllowedIPs");
      }
      if (call.tool == wg::NetworkTool::Ip && call.arguments.size() > 3 && call.arguments[1] == "route") {
        route_installed = true;
        check(call.arguments[3] == "10.77.0.2/32", "Device installed a broad peer route");
      }
    }
    check(peer_installed, "Admission never triggered peer installation");
    if (fail == 0) check(route_installed, "Admitted peer has no explicit route");
    device.stop(device_deadline());
    check(commands.links.size() == 1 && !commands.firewall.empty(), "Peer failure did not remove device state safely");
  }
  bool installed = false;
  paired_session(fixture, false, true, false, {}, {}, [&](const wg::AdmittedSession &) { installed = true; });
  check(!installed, "Failed admission reached the device setup callback");
  paired_session(fixture, false, false, false, {}, {},
      [&](const wg::AdmittedSession &session) { session.synchronize("local-label"); },
      [&](const wg::AdmittedSession &session) { session.synchronize("different-label"); });
}

void udp_pair(int (&sockets)[2]) {
  sockaddr_in endpoints[2]{};
  for (unsigned i = 0; i < 2; ++i) {
    sockets[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    endpoints[i].sin_family = AF_INET; endpoints[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check(sockets[i] >= 0 && bind(sockets[i], reinterpret_cast<sockaddr *>(&endpoints[i]), sizeof(endpoints[i])) == 0,
          "Cannot bind test UDP pair");
    socklen_t size = sizeof(endpoints[i]);
    check(getsockname(sockets[i], reinterpret_cast<sockaddr *>(&endpoints[i]), &size) == 0, "Cannot inspect test UDP port");
  }
  for (unsigned i = 0; i < 2; ++i) check(connect(sockets[i], reinterpret_cast<sockaddr *>(&endpoints[1 - i]),
      sizeof(endpoints[i])) == 0, "Cannot connect test UDP pair");
}

void probe_tests(Fixture &fixture) {
  // Real UDP and TLS, with synthetic attestation, without modifying the host's network.
  for (auto mtu : {1280, 1400, 1420}) {
    int sockets[2]; udp_pair(sockets);
    paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
      close(sockets[1]);
      wg::probe_connected_udp(sockets[0], session, device_deadline(), static_cast<std::uint16_t>(mtu));
    }, [&](const wg::AdmittedSession &session) {
      close(sockets[0]);
      wg::probe_connected_udp(sockets[1], session, device_deadline(), static_cast<std::uint16_t>(mtu));
    });
    close(sockets[0]); close(sockets[1]);
  }
  std::string captured_path = fixture.directory.path + "/old-probe.bin";
  int capture_sockets[2]; udp_pair(capture_sockets);
  paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
    pollfd item{capture_sockets[0], POLLIN, 0};
    if (poll(&item, 1, 1000) <= 0) throw wg::Error("No server probe to capture");
    std::array<char, 1372> packet{};
    if (recv(capture_sockets[0], packet.data(), packet.size(), MSG_PEEK) != static_cast<ssize_t>(packet.size())) {
      throw wg::Error("Wrong captured probe size");
    }
    wg::write_public_file(captured_path, {packet.data(), packet.size()});
    wg::probe_connected_udp(capture_sockets[0], session, device_deadline(), 1400);
  }, [&](const wg::AdmittedSession &session) {
    wg::probe_connected_udp(capture_sockets[1], session, device_deadline(), 1400);
  });
  close(capture_sockets[0]); close(capture_sockets[1]);
  auto old_probe = wg::read_public_file(captured_path);
  int loss_sockets[2]; udp_pair(loss_sockets);
  paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
    wg::probe_connected_udp(loss_sockets[0], session, device_deadline(), 1400);
  }, [&](const wg::AdmittedSession &session) {
    // Discard the first client packet; retransmission must still complete in both directions.
    pollfd item{loss_sockets[1], POLLIN, 0};
    if (poll(&item, 1, 1000) <= 0) throw wg::Error("No client probe to drop");
    std::array<char, 1420> discarded{};
    recv(loss_sockets[1], discarded.data(), discarded.size(), 0);
    wg::probe_connected_udp(loss_sockets[1], session, device_deadline(), 1400);
  });
  close(loss_sockets[0]); close(loss_sockets[1]);
  for (bool replay : {false, true}) {
    int reflected[2]; udp_pair(reflected);
    paired_session(fixture, false, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
      wg::probe_connected_udp(reflected[0], session,
          wg::Deadline(wg::Deadline::Clock::now() + std::chrono::milliseconds(180)), 1400);
    }, [&](const wg::AdmittedSession &session) {
      pollfd item{reflected[1], POLLIN, 0};
      if (poll(&item, 1, 1000) <= 0) throw wg::Error("No client probe to reflect");
      std::array<char, 1372> packet{};
      auto n = recv(reflected[1], packet.data(), packet.size(), 0);
      if (n != static_cast<ssize_t>(packet.size())) throw wg::Error("Wrong reflected probe size");
      if (replay) send(reflected[1], old_probe.data(), old_probe.size(), MSG_NOSIGNAL);
      else send(reflected[1], packet.data(), packet.size(), MSG_NOSIGNAL);
      session.synchronize("overlay-probed");
    });
    close(reflected[0]); close(reflected[1]);
  }
  int sockets[2]; udp_pair(sockets);
  paired_session(fixture, false, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
    close(sockets[1]);
    wg::probe_connected_udp(sockets[0], session,
        wg::Deadline(wg::Deadline::Clock::now() + std::chrono::milliseconds(180)), 1400);
  }, [&](const wg::AdmittedSession &session) {
    // Full-size unauthenticated packets, including a forged ACK with a copied challenge, never count.
    std::array<char, 1372> packet{};
    pollfd item{sockets[1], POLLIN, 0};
    if (poll(&item, 1, 1000) <= 0) throw wg::Error("Test probe did not arrive");
    if (recv(sockets[1], packet.data(), packet.size(), 0) != static_cast<ssize_t>(packet.size())) throw wg::Error("Wrong probe size");
    packet[6] = 1; packet[7] = 2;
    std::copy_n(packet.begin() + 8, 32, packet.begin() + 40);
    send(sockets[1], packet.data(), packet.size(), MSG_NOSIGNAL);
    session.synchronize("overlay-probed");
  });
  close(sockets[0]); close(sockets[1]);
  check(waitpid(-1, nullptr, WNOHANG) < 0 && errno == ECHILD, "Probe test left a detached child");
}

void supervisor_tests(Fixture &fixture) {
  using Clock = wg::Deadline::Clock;
  auto base = Clock::now();
  auto wall = static_cast<std::uint64_t>(std::time(nullptr));
  wg::LeaseSupervisor unauthenticated(fixture.a, fixture.membership, base, wall);
  check(!unauthenticated.ready(base, wall) && unauthenticated.permits(base, wall).empty(),
        "Membership alone enabled supervised workloads");
  check(unauthenticated.heartbeat_requests(base, wall, true).empty(), "Unsigned heartbeat capability was created");
  check(!unauthenticated.update_membership(fixture.membership, base + std::chrono::seconds(30), wall - 30),
        "Identical grant renewed its monotonic lease after clock rollback");
  rejected([&] { unauthenticated.check(base + std::chrono::seconds(121), wall - 30, false); });
  auto extended = fixture.membership;
  extended.not_before += 1; extended.expires_at += 10;
  check(unauthenticated.update_membership(extended, base, wall), "Increasing valid lease extension was rejected");
  rejected([&] { unauthenticated.update_membership(fixture.membership, base, wall); });
  extended.members.front().wireguard_public_key_b64 = fixture.identity_b.wireguard_public_key_b64;
  rejected([&] { unauthenticated.update_membership(extended, base, wall); });

  // Keep a real fresh TLS session alive while constructing the in-memory heartbeat capabilities.
  auto old_heartbeat_path = fixture.directory.path + "/old-heartbeat.bin";
  int sockets[2]; udp_pair(sockets);
  paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
    auto now = Clock::now(); auto wall = static_cast<std::uint64_t>(std::time(nullptr));
    wg::LeaseSupervisor supervisor(fixture.a, session.membership(), now, wall);
    supervisor.authorize(session, now, wall);
    check(!supervisor.ready(now, wall), "Probe alone ignored required peer group readiness");
    auto requests = supervisor.heartbeat_requests(now, wall, true);
    check(requests.size() == 1, "Supervisor failed to challenge the admitted peer");
    wg::write_public_file(old_heartbeat_path, requests[0].bytes);
    send(sockets[0], requests[0].bytes.data(), requests[0].bytes.size(), MSG_NOSIGNAL);
    pollfd item{sockets[0], POLLIN, 0};
    check(poll(&item, 1, 1000) > 0, "Test heartbeat reply missing");
    std::array<char, 512> buffer{};
    auto size = recv(sockets[0], buffer.data(), buffer.size(), 0);
    check(size > 0, "Empty test heartbeat");
    std::string reply(buffer.data(), static_cast<std::size_t>(size));
    auto corrupt = reply; corrupt.back() ^= 1;
    supervisor.receive_heartbeat("b", corrupt, now, wall, true);
    check(!supervisor.ready(now, wall), "Forged heartbeat made peer ready");
    supervisor.receive_heartbeat("unknown", reply, now, wall, true);
    check(!supervisor.ready(now, wall), "Heartbeat from unknown node made peer ready");
    supervisor.receive_heartbeat("b", reply, now, wall, true);
    check(supervisor.ready(now, wall), "Fresh authenticated heartbeat failed readiness");
    auto permits = supervisor.permits(now, wall);
    check(permits.size() == 1 && permits[0].until <= now + std::chrono::seconds(fixture.a.timeouts.peer_seconds),
          "Heartbeat permit exceeded peer liveness bound");
    auto exchange = [&](unsigned seconds) {
      auto request = supervisor.heartbeat_requests(now + std::chrono::seconds(seconds), wall + seconds, true);
      check(request.size() == 1, "Renewed heartbeat challenge missing");
      send(sockets[0], request[0].bytes.data(), request[0].bytes.size(), MSG_NOSIGNAL);
      check(poll(&item, 1, 1000) > 0, "Renewed heartbeat reply missing");
      auto length = recv(sockets[0], buffer.data(), buffer.size(), 0);
      check(length > 0, "Renewed heartbeat reply empty");
      return std::string(buffer.data(), static_cast<std::size_t>(length));
    };
    auto older = exchange(1), newer = exchange(2);
    supervisor.receive_heartbeat("b", newer, now + std::chrono::seconds(2), wall + 2, true);
    check(!supervisor.ready(now + std::chrono::seconds(2), wall + 2), "Unconfigured required peer retained readiness");
    supervisor.receive_heartbeat("b", older, now + std::chrono::seconds(2), wall + 2, true);
    check(!supervisor.ready(now + std::chrono::seconds(2), wall + 2), "Older ACK restored obsolete group readiness");
    auto delayed = exchange(3);
    supervisor.receive_heartbeat("b", delayed, now + std::chrono::seconds(29), wall + 29, true);
    check(supervisor.ready(now + std::chrono::seconds(29), wall + 29), "Valid delayed ACK was rejected before its bound");
    supervisor.receive_heartbeat("b", delayed, now + std::chrono::seconds(32), wall + 32, true);
    check(!supervisor.ready(now + std::chrono::seconds(34), wall + 34), "Delayed or replayed ACK extended its issuance deadline");
    rejected([&] { supervisor.check(now + std::chrono::seconds(34), wall + 34, true); });
    check(supervisor.permits(now + std::chrono::seconds(34), wall + 34).empty(), "Expired peer retained workload permissions");
    auto optional_config = fixture.a; optional_config.peers[0].required = false;
    wg::LeaseSupervisor optional(optional_config, session.membership(), now, wall);
    check(!optional.ready(now, wall), "All-optional group was ready without an admitted peer");
    optional.authorize(session, now, wall);
    check(optional.expired_optional(now + std::chrono::seconds(31), wall + 31) == std::vector<std::string>{"b"},
          "Expired optional peer was not scheduled for removal");
    auto extension = session.membership(); extension.expires_at += 10;
    supervisor.update_membership(extension, now, wall);
    rejected([&] { supervisor.authorize(session, now, wall); });
    auto snapshot = Json::parse(supervisor.status("stopping", false, now, wall, "fixture failure"));
    check(snapshot["workload_ready"] == false && snapshot["peers"][0]["boot_id"] == fixture.identity_b.boot_id &&
        snapshot["rejection_reason"] == "fixture failure", "Status omitted peer identity or withdrawal reason");
    check(snapshot.dump().find(session.probe_key()) == std::string::npos, "Status leaked session key");
    supervisor.reject("b", "bad renewal");
    check(supervisor.heartbeat_requests(now + std::chrono::seconds(1), wall + 1, true).empty(), "Rejected peer retained heartbeat keys");
    session.synchronize("supervisor-tests");
  }, [&](const wg::AdmittedSession &session) {
    auto now = Clock::now(); auto wall = static_cast<std::uint64_t>(std::time(nullptr));
    wg::LeaseSupervisor supervisor(fixture.b, session.membership(), now, wall);
    supervisor.authorize(session, now, wall);
    for (bool configured : {true, true, false, true}) {
      pollfd item{sockets[1], POLLIN, 0};
      if (poll(&item, 1, 1000) <= 0) throw wg::Error("No test heartbeat request");
      std::array<char, 512> buffer{};
      auto size = recv(sockets[1], buffer.data(), buffer.size(), 0);
      if (size <= 0) throw wg::Error("No heartbeat bytes");
      auto reply = supervisor.receive_heartbeat("a", {buffer.data(), static_cast<std::size_t>(size)}, now, wall, configured);
      if (reply.empty()) throw wg::Error("Test heartbeat MAC rejected");
      send(sockets[1], reply.data(), reply.size(), MSG_NOSIGNAL);
    }
    session.synchronize("supervisor-tests");
  });
  close(sockets[0]); close(sockets[1]);
  auto old_heartbeat = wg::read_public_file(old_heartbeat_path);
  paired_session(fixture, true, false, false, {}, {}, [&](const wg::AdmittedSession &session) {
    session.synchronize("heartbeat-replay-tests");
  }, [&](const wg::AdmittedSession &session) {
    auto now = Clock::now(); auto wall = static_cast<std::uint64_t>(std::time(nullptr));
    wg::LeaseSupervisor supervisor(fixture.b, session.membership(), now, wall);
    supervisor.authorize(session, now, wall);
    if (!supervisor.receive_heartbeat("a", old_heartbeat, now, wall, true).empty()) {
      throw wg::Error("Previous TLS session heartbeat passed fresh capability MAC");
    }
    session.synchronize("heartbeat-replay-tests");
  });
}

void status_and_notification_tests(Fixture &fixture) {
  auto state = fixture.directory.path + "/status-state";
  wg::write_runtime_status(state, "{\"workload_ready\":true}\n");
  wg::write_runtime_status(state, "{\"workload_ready\":false}\n");
  check(Json::parse(wg::read_private_file(state + "/status.json"))["workload_ready"] == false,
        "Runtime status was not replaced atomically");
  std::filesystem::remove(state + "/status.json");
  symlink((fixture.directory.path + "/victim").c_str(), (state + "/status.json").c_str());
  rejected([&] { wg::write_runtime_status(state, "overwrite"); });
  check(!std::filesystem::exists(fixture.directory.path + "/victim"), "Status followed a symlink");
  std::filesystem::remove(state + "/status.json");
  wg::write_runtime_status(state, "public status");
  chmod((state + "/status.json").c_str(), 0644);
  rejected([&] { wg::write_runtime_status(state, "unsafe status"); });
  auto path = fixture.directory.path + "/notify.sock";
  int socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  sockaddr_un address{}; address.sun_family = AF_UNIX;
  check(path.size() < sizeof(address.sun_path), "Notification test path is too long");
  std::copy(path.begin(), path.end(), address.sun_path);
  check(socket_fd >= 0 && bind(socket_fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0,
        "Cannot bind test notification socket");
  setenv("NOTIFY_SOCKET", path.c_str(), 1); setenv("WATCHDOG_USEC", "2000000", 1); unsetenv("WATCHDOG_PID");
  {
    wg::ServiceNotifier notifier;
    notifier.notify("READY=1\nSTATUS=test"); notifier.watchdog(wg::Deadline::Clock::now());
    notifier.notify("STOPPING=1");
    std::array<char, 256> message{};
    for (std::string expected : {"READY=1\nSTATUS=test", "WATCHDOG=1", "STOPPING=1"}) {
      auto length = recv(socket_fd, message.data(), message.size(), 0);
      check(length > 0 && std::string(message.data(), static_cast<std::size_t>(length)) == expected,
            "Systemd readiness/watchdog/withdrawal notification changed");
    }
  }
  setenv("WATCHDOG_USEC", "invalid", 1);
  rejected([&] { wg::ServiceNotifier notifier; });
  setenv("WATCHDOG_USEC", "2000000", 1); setenv("WATCHDOG_PID", "1", 1);
  if (getpid() != 1) {
    wg::ServiceNotifier notifier;
    notifier.watchdog(wg::Deadline::Clock::now());
    std::array<char, 256> message{};
    check(recv(socket_fd, message.data(), message.size(), 0) < 0 && errno == EAGAIN,
          "Watchdog notification ignored another process's WATCHDOG_PID");
  }
  unsetenv("WATCHDOG_PID");
  unsetenv("NOTIFY_SOCKET"); unsetenv("WATCHDOG_USEC");
  close(socket_fd);
}

void cleanup_tests(Fixture &fixture) {
  FakeNetworkCommands stale;
  stale.public_key = fixture.identity_a.wireguard_public_key_b64;
  {
    wg::RuntimeIdentity identity(fixture.a, fixture.directory.path + "/state-a");
    FakeNetworkCommands commands; commands.public_key = stale.public_key;
    wg::WireGuardDevice device(fixture.a, commands);
    device.start(identity, device_deadline());
    stale = commands;  // Preserve the kernel view as if this process had crashed without destructors.
    auto before = stale.mutations;
    rejected([&] { wg::cleanup_overlay(fixture.a, fixture.directory.path + "/state-a", stale, device_deadline()); });
    check(stale.mutations == before, "Cleanup disturbed a live service before acquiring its identity lock");
  }
  wg::cleanup_overlay(fixture.a, fixture.directory.path + "/state-a", stale, device_deadline());
  check(stale.links.size() == 1 && !stale.firewall.empty(), "Crash cleanup failed to remove owned interface and retain guards");
  auto status = Json::parse(wg::read_private_file(fixture.directory.path + "/state-a/status.json"));
  check(status["workload_ready"] == false && status["state"] == "stopped", "Crash cleanup retained readiness");
  wg::cleanup_overlay(fixture.a, fixture.directory.path + "/state-a", stale, device_deadline());
  check(stale.links.size() == 1, "Repeated crash cleanup changed unrelated interfaces");
  stale.links.push_back({{"ifname", "wg0"}, {"ifalias", "another-owner"}});
  rejected([&] { wg::cleanup_overlay(fixture.a, fixture.directory.path + "/state-a", stale, device_deadline()); });
  check(stale.links.size() == 2, "Cleanup adopted another owner's interface");
}

void integration_peer(Fixture &fixture, bool server, const char *namespace_path) {
  int ns = open(namespace_path, O_RDONLY | O_CLOEXEC);
  check(ns >= 0 && setns(ns, CLONE_NEWNET) == 0, "Cannot enter test network namespace");
  close(ns);
  const auto &config = server ? fixture.b : fixture.a;
  const auto &other = config.peers.front();
  wg::RuntimeIdentity identity(config, fixture.directory.path + (server ? "/state-b" : "/state-a"));
  auto commands = wg::real_network_commands();
  wg::WireGuardDevice device(config, *commands);
  wg::Deadline deadline(wg::Deadline::Clock::now() + std::chrono::seconds(25));
  device.start(identity, deadline);
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  endpoint.sin_port = htons(config.admission_port);
  int socket_fd = -1;
  if (server) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    check(listener >= 0 && bind(listener, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint)) == 0 &&
        listen(listener, 1) == 0, "Cannot listen for integration admission");
    deadline.wait(listener, POLLIN);
    socket_fd = accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    close(listener);
  } else {
    check(inet_pton(AF_INET, other.endpoint_ipv4.c_str(), &endpoint.sin_addr) == 1, "Bad integration endpoint");
    for (;;) {
      deadline.check();
      int candidate = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      check(candidate >= 0, "Cannot open integration TCP socket");
      auto result = connect(candidate, reinterpret_cast<sockaddr *>(&endpoint), sizeof(endpoint));
      if (result < 0 && errno == EINPROGRESS) {
        deadline.wait(candidate, POLLOUT);
        int error = 0; socklen_t length = sizeof(error);
        result = getsockopt(candidate, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0 ? 0 : -1;
      }
      if (result == 0) { socket_fd = candidate; break; }
      close(candidate);
      deadline.wait(-1, 0);
    }
  }
  check(socket_fd >= 0, "Cannot connect integration admission");
  FixtureEvidence evidence;
  auto output = wg::admit_connected_socket(socket_fd, server, config, identity.identity(), fixture.envelope,
      other.node_id, evidence, deadline, [&](const wg::AdmittedSession &session) {
        device.install_peer(session, deadline);
        session.synchronize("device-installed");
        wg::probe_overlay(config, session, deadline);
        // Normal inference UDP remains blocked even after the encrypted control probe succeeds.
        int workload = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in local{}, remote{};
        local.sin_family = remote.sin_family = AF_INET;
        local.sin_port = remote.sin_port = htons(40000);
        check(inet_pton(AF_INET, config.overlay_ipv4.c_str(), &local.sin_addr) == 1 &&
            inet_pton(AF_INET, other.overlay_ipv4.c_str(), &remote.sin_addr) == 1, "Bad integration overlay address");
        check(workload >= 0 && bind(workload, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0,
              "Cannot bind integration workload socket");
        session.synchronize("workload-bound");
        sendto(workload, "blocked", 7, 0, reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
        session.synchronize("workload-sent");
        pollfd item{workload, POLLIN, 0};
        check(poll(&item, 1, 150) == 0, "Closed workload gate allowed inference UDP");
        session.synchronize("workload-blocked");
        device.check_inventory(deadline);
        auto until = wg::Deadline::Clock::now() + std::chrono::seconds(6);
        check(device.update_workload({{other.node_id, until}}, until, deadline), "Cannot open timed integration gate");
        session.synchronize("workload-enabled");
        check(sendto(workload, "allowed", 7, 0, reinterpret_cast<sockaddr *>(&remote), sizeof(remote)) == 7,
              "Cannot send authorized inference UDP");
        session.synchronize("workload-allowed-sent");
        check(poll(&item, 1, 1000) > 0, "Timed workload gate failed to allow authorized UDP");
        std::array<char, 32> message{};
        auto length = recv(workload, message.data(), message.size(), 0);
        check(length == 7 && std::string(message.data(), 7) == "allowed", "Authorized workload packet changed");
        session.synchronize("workload-allowed");
        // Simulate a dead/hung refresher: the kernel must expire permissions while WireGuard stays up.
        auto expiry_wait = wg::Deadline::Clock::now() + std::chrono::seconds(5);
        while (wg::Deadline::Clock::now() < expiry_wait) deadline.wait(-1, 0);
        device.check_inventory(deadline);
        sendto(workload, "expired", 7, 0, reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
        session.synchronize("workload-expired-sent");
        check(poll(&item, 1, 150) == 0, "Expired kernel permission retained workload access");
        close(workload);
        session.synchronize("workload-expired");
      });
  check(Json::parse(output)["workload_ready"] == false, "Integration advertised workload readiness");
  close(socket_fd);
  device.stop(deadline);
  auto links = Json::parse(commands->run(wg::NetworkTool::Ip, {"-j", "link", "show"}, {}, -1, deadline));
  for (const auto &link : links) check(link["ifname"] != config.interface, "Integration cleanup retained WireGuard");
  // Restart must recognize exactly the retained closed firewall, without opening or flushing it.
  device.start(identity, deadline);
  check(commands->run(wg::NetworkTool::WireGuard, {"show", config.interface, "peers"}, {}, -1, deadline).empty(),
        "Restart recovered historical kernel peers");
  commands->run(wg::NetworkTool::Ip, {"link", "delete", "dev", config.interface}, {}, -1, deadline);
  rejected([&] { device.check_inventory(deadline); });
  device.stop(deadline);
}

void network_integration(const char *namespace_a, const char *namespace_b) {
  Fixture fixture;
  fixture.a.peers[0].endpoint_ipv4 = "192.0.2.2";
  fixture.b.peers[0].endpoint_ipv4 = "192.0.2.1";
  auto child = fork();
  check(child >= 0, "Cannot start namespace peer");
  if (child == 0) {
    try { integration_peer(fixture, false, namespace_a); _exit(0); }
    catch (const std::exception &error) { std::cerr << "Namespace A: " << error.what() << '\n'; _exit(1); }
  }
  try { integration_peer(fixture, true, namespace_b); }
  catch (...) { kill(child, SIGKILL); waitpid(child, nullptr, 0); throw; }
  int status = 0;
  check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "Namespace A failed");
  std::cout << "WireGuard namespace integration passed (real kernel networking; synthetic attestation)\n";
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
    if (argc == 4 && std::string_view(argv[1]) == "--network-integration") {
      network_integration(argv[2], argv[3]);
      return 0;
    }
    worker_tests(); policy_tests(); quote_parser_tests(); fake_tee_tests();
    Fixture fixture;
    transcript_tests(fixture);
    device_tests(fixture);
    probe_tests(fixture);
    supervisor_tests(fixture);
    status_and_notification_tests(fixture);
    cleanup_tests(fixture);
    auto old_quote = paired_session(fixture, true);
    check(!old_quote.empty(), "No fresh test quote generated");
    auto pinned_a = fixture.a, pinned_b = fixture.b;
    fixture.a.image_policy = fixture.b.image_policy = wg::ImagePolicy::SignedMembership;
    fixture.a.allowed_image_hashes_hex.clear(); fixture.b.allowed_image_hashes_hex.clear();
    paired_session(fixture, true);
    paired_session(fixture, false, true);  // Authentic membership cannot make mismatched evidence valid.
    auto wrong_image = fixture.membership;
    wrong_image.members[1].image_hash_hex = std::string(64, 'b');
    fixture.envelope = wg::sign_membership(wrong_image, fixture.signer);
    paired_session(fixture, false);  // Certificate quote must match the exact signed image.
    fixture.envelope = wg::sign_membership(fixture.membership, fixture.signer);
    fixture.a = pinned_a; fixture.b = pinned_b;
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
