#include "WireGuardAdmission.h"

#include "tee/cocoon/Tee.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <ctime>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace cocoon::wireguard {
namespace {

constexpr std::size_t max_quote = 32768;
constexpr char record_domain[] = "cocoon/wg-admission/v1";
constexpr char hello_domain[] = "CWGA1";
constexpr char exporter_label[] = "EXPERIMENTAL-cocoon-wg-admission-v1";

struct ErrorQueueGuard {
  ErrorQueueGuard() { ERR_clear_error(); }
  ~ErrorQueueGuard() { ERR_clear_error(); }
};

void require(bool condition, const char *message) {
  if (!condition) throw Error(message);
}

struct Fd {
  int value;
  explicit Fd(int fd) : value(fd) { require(fd >= 0, "Cannot open admission socket"); }
  Fd(const Fd &) = delete;
  Fd(Fd &&other) noexcept : value(std::exchange(other.value, -1)) {}
  ~Fd() { if (value >= 0) close(value); }
};

std::uint64_t wall_time() {
  auto now = std::time(nullptr);
  require(now >= 0, "Cannot read wall clock");
  return static_cast<std::uint64_t>(now);
}

std::string digest(std::string_view input, const EVP_MD *algorithm) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> output{};
  unsigned size = 0;
  require(EVP_Digest(input.data(), input.size(), output.data(), &size, algorithm, nullptr) == 1,
          "Cannot hash admission context");
  return {reinterpret_cast<const char *>(output.data()), size};
}

std::string hex(std::string_view input) {
  constexpr char digits[] = "0123456789abcdef";
  std::string output;
  for (unsigned char c : input) { output += digits[c >> 4]; output += digits[c & 15]; }
  return output;
}

std::string base64(std::string_view input) {
  std::string output(4 * ((input.size() + 2) / 3), '\0');
  require(EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                          reinterpret_cast<const unsigned char *>(input.data()), static_cast<int>(input.size())) ==
              static_cast<int>(output.size()), "Cannot encode public TLS identity");
  return output;
}

void integer(std::string &out, std::uint64_t value, unsigned width) {
  for (unsigned i = width; i > 0; --i) out += static_cast<char>(value >> (8 * (i - 1)));
}

std::uint64_t number(std::string_view input) {
  std::uint64_t out = 0;
  for (unsigned char c : input) out = (out << 8) | c;
  return out;
}

void sized(std::string &out, std::string_view value) {
  require(!value.empty() && value.size() <= 64, "Invalid admission node identifier");
  integer(out, value.size(), 2);
  out += value;
}

const Member &member(const Membership &membership, std::string_view node) {
  auto found = std::find_if(membership.members.begin(), membership.members.end(),
                             [&](const auto &m) { return m.node_id == node; });
  require(found != membership.members.end(), "Admission node is outside signed membership");
  return *found;
}

std::string tls_key(X509 *certificate) {
  require(certificate, "Missing TLS certificate");
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(certificate), EVP_PKEY_free);
  require(key && EVP_PKEY_base_id(key.get()) == EVP_PKEY_ED25519, "Admission requires Ed25519 TLS identities");
  std::string out(32, '\0');
  std::size_t size = out.size();
  require(EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char *>(out.data()), &size) == 1 &&
              size == out.size(), "Invalid TLS public key");
  require(X509_NAME_cmp(X509_get_subject_name(certificate), X509_get_issuer_name(certificate)) == 0 &&
              X509_verify(certificate, key.get()) == 1, "Admission requires a valid self-signed certificate");
  require(X509_cmp_current_time(X509_get0_notBefore(certificate)) < 0 &&
              X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0, "TLS certificate is outside its validity");
  return out;
}

std::string extension(X509 *certificate, const char *oid) {
  std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> object(OBJ_txt2obj(oid, 1), ASN1_OBJECT_free);
  require(static_cast<bool>(object), "Cannot construct attestation OID");
  auto index = X509_get_ext_by_OBJ(certificate, object.get(), -1);
  require(index >= 0 && X509_get_ext_by_OBJ(certificate, object.get(), index) < 0,
          "Missing or duplicate TDX certificate evidence");
  auto ext = X509_get_ext(certificate, index);
  require(X509_EXTENSION_get_critical(ext) == 1, "TDX evidence extensions must be critical");
  auto data = X509_EXTENSION_get_data(ext);
  auto size = ASN1_STRING_length(data);
  require(size > 0 && size <= static_cast<int>(max_quote), "Certificate evidence size is out of bounds");
  return {reinterpret_cast<const char *>(ASN1_STRING_get0_data(data)), static_cast<std::size_t>(size)};
}

Evidence verify_certificate(X509 *certificate, const Config &config, EvidenceProvider &provider,
                            const Deadline &deadline) {
  auto public_key = tls_key(certificate);
  for (int i = 0; i < X509_get_ext_count(certificate); ++i) {
    auto ext = X509_get_ext(certificate, i);
    std::array<char, 128> oid{};
    auto size = OBJ_obj2txt(oid.data(), static_cast<int>(oid.size()), X509_EXTENSION_get_object(ext), 1);
    require(size > 0 && size < static_cast<int>(oid.size()), "Invalid certificate OID");
    auto name = std::string_view(oid.data(), static_cast<std::size_t>(size));
    require(!name.starts_with("1.3.6.1.4.1.12345.") || name == "1.3.6.1.4.1.12345.1" ||
                name == "1.3.6.1.4.1.12345.2", "Non-TDX attestation extensions are forbidden");
    require(!X509_EXTENSION_get_critical(ext) || X509_supported_extension(ext) ||
                name == "1.3.6.1.4.1.12345.1" || name == "1.3.6.1.4.1.12345.2",
            "Unknown critical certificate extension");
  }
  require(extension(certificate, "1.3.6.1.4.1.12345.2") == public_key,
          "Certificate user claims do not match its TLS key");
  auto evidence = provider.verify(extension(certificate, "1.3.6.1.4.1.12345.1"), deadline);
  check_evidence(evidence, digest(public_key, EVP_sha512()), evidence.image_hash_hex);
  require(std::find(config.allowed_image_hashes_hex.begin(), config.allowed_image_hashes_hex.end(),
                    evidence.image_hash_hex) != config.allowed_image_hashes_hex.end(),
          "TLS certificate image is outside admission policy");
  return evidence;
}

class Session {
 public:
  Session(SSL *ssl, int socket, const Deadline &deadline, std::function<void()> progress = {})
      : ssl_(ssl), socket_(socket), deadline_(deadline), progress_(std::move(progress)) {}

  void handshake() {
    for (;;) {
      deadline_.check();
      ERR_clear_error();
      auto result = SSL_do_handshake(ssl_);
      if (result == 1) break;
      retry(result);
    }
    require(SSL_version(ssl_) == TLS1_3_VERSION && !SSL_session_reused(ssl_),
            "Admission requires a full TLS 1.3 handshake");
  }
  void send(unsigned char type, std::string_view value) {
    require(value.size() <= max_quote, "Admission frame exceeds limit");
    std::string frame;
    integer(frame, value.size() + 1, 4);
    frame += static_cast<char>(type);
    frame += value;
    transfer(frame.data(), frame.size(), true);
  }
  std::string receive(unsigned char expected) {
    std::array<char, 4> header{};
    transfer(header.data(), header.size(), false);
    auto size = number({header.data(), header.size()});
    auto limit = expected == 1 ? 137U : (expected == 3 || expected == 4) ? 33U : max_quote + 1;
    require(size > 1 && size <= limit, "Admission frame size is out of bounds");
    std::string out(static_cast<std::size_t>(size), '\0');
    transfer(out.data(), out.size(), false);
    require(static_cast<unsigned char>(out.front()) == expected, "Unexpected admission message");
    out.erase(0, 1);
    return out;
  }

 private:
  void retry(int result) {
    auto error = SSL_get_error(ssl_, result);
    if (error == SSL_ERROR_WANT_READ) deadline_.wait(socket_, POLLIN);
    else if (error == SSL_ERROR_WANT_WRITE) deadline_.wait(socket_, POLLOUT);
    else throw Error("Admission TLS connection failed");
  }
  void transfer(char *data, std::size_t size, bool write) {
    while (size) {
      deadline_.check();
      if (progress_) progress_();
      std::size_t count = 0;
      ERR_clear_error();
      auto result = write ? SSL_write_ex(ssl_, data, size, &count) : SSL_read_ex(ssl_, data, size, &count);
      if (result == 1) { data += count; size -= count; }
      else retry(result);
    }
  }
  SSL *ssl_;
  int socket_;
  const Deadline &deadline_;
  std::function<void()> progress_;
};

std::string hello(std::string_view node, std::string_view nonce, std::string_view membership_hash) {
  std::string out(hello_domain, sizeof(hello_domain));
  sized(out, node);
  out += nonce;
  out += membership_hash;
  return out;
}

std::string parse_hello(std::string_view input, std::string_view peer, std::string_view membership_hash) {
  require(input.size() >= sizeof(hello_domain) + 2 + 1 + 64 &&
              input.substr(0, sizeof(hello_domain)) == std::string_view(hello_domain, sizeof(hello_domain)),
          "Invalid admission hello");
  input.remove_prefix(sizeof(hello_domain));
  auto size = number(input.substr(0, 2));
  input.remove_prefix(2);
  require(size == peer.size() && input.size() == size + 64 && input.substr(0, size) == peer,
          "Unexpected admission peer identity");
  input.remove_prefix(size);
  require(input.substr(32) == membership_hash, "Admission membership digest differs");
  auto nonce = input.substr(0, 32);
  require(nonce != std::string(32, '\0'), "Admission nonce must not be zero");
  return std::string(nonce);
}

Fd connect_peer(const Peer &peer, const Deadline &deadline) {
  unsigned backoff = 100;
  for (;;) {
    deadline.check();
    Fd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(peer.admission_endpoint_port);
    require(inet_pton(AF_INET, peer.endpoint_ipv4.c_str(), &address.sin_addr) == 1, "Invalid peer endpoint");
    auto result = connect(socket.value, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    if (result == 0) return socket;
    if (errno == EINPROGRESS) {
      deadline.wait(socket.value, POLLOUT);
      int error = 0;
      socklen_t size = sizeof(error);
      require(getsockopt(socket.value, SOL_SOCKET, SO_ERROR, &error, &size) == 0, "Cannot inspect connection");
      if (error == 0) return socket;
    }
    auto end = std::min(deadline.end(), Deadline::Clock::now() + std::chrono::milliseconds(backoff));
    while (Deadline::Clock::now() < end) deadline.wait(-1, 0);
    backoff = std::min(backoff * 2, 2000U);
  }
}

Fd accept_peer(std::uint16_t port, const Deadline &deadline) {
  Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  int enabled = 1;
  require(setsockopt(listener.value, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0,
          "Cannot configure admission listener");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  require(bind(listener.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 &&
              listen(listener.value, 8) == 0, "Cannot bind admission listener");
  for (;;) {
    deadline.check();
    auto connection = accept4(listener.value, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (connection >= 0) return Fd(connection);
    require(errno == EAGAIN || errno == EINTR, "Admission accept failed");
    deadline.wait(listener.value, POLLIN);
  }
}

}  // namespace

Deadline::Deadline(Clock::time_point end, std::function<bool()> cancelled, std::function<void()> progress)
    : end_(end), cancelled_(std::move(cancelled)), progress_(std::move(progress)) {}
void Deadline::check() const {
  require(!cancelled_ || !cancelled_(), "Admission cancelled");
  require(Clock::now() < end_, "Admission deadline exceeded");
  if (progress_) {
    progress_();
    require(!cancelled_ || !cancelled_(), "Admission cancelled");
    require(Clock::now() < end_, "Admission deadline exceeded");
  }
}
void Deadline::wait(int fd, short events) const {
  for (;;) {
    check();
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - Clock::now()).count();
    pollfd item{fd, events, 0};
    auto result = poll(&item, 1, static_cast<int>(std::clamp<std::int64_t>(left, 1, 100)));
    if (result > 0 || (result == 0 && fd < 0)) return;
    require(result >= 0 || errno == EINTR, "Admission poll failed");
  }
}
Deadline::Clock::time_point Deadline::end() const { return end_; }
Deadline Deadline::within(std::chrono::seconds duration) const {
  return Deadline(std::min(end_, Clock::now() + duration), cancelled_, progress_);
}

std::string admission_record(const Membership &membership, std::string_view client_node,
                             std::string_view server_node, std::string_view client_nonce,
                             std::string_view server_nonce, std::string_view client_tls_key,
                             std::string_view server_tls_key, std::string_view channel_binding) {
  require(client_node != server_node, "Admission peers must differ");
  member(membership, client_node); member(membership, server_node);
  require(client_nonce.size() == 32 && server_nonce.size() == 32 && client_tls_key.size() == 32 &&
              server_tls_key.size() == 32 && channel_binding.size() == 32 &&
              client_nonce != std::string(32, '\0') && server_nonce != std::string(32, '\0') &&
              client_nonce != server_nonce, "Invalid admission nonces, TLS identities, or channel binding");
  auto membership_bytes = encode_membership(membership);
  std::string out(record_domain, sizeof(record_domain));
  integer(out, membership_bytes.size(), 4);
  out += membership_bytes;
  sized(out, client_node); sized(out, server_node);
  out += client_nonce; out += server_nonce; out += client_tls_key; out += server_tls_key; out += channel_binding;
  return out;
}

std::string admission_reportdata(std::string_view record, bool prover_is_server) {
  std::string input(record);
  input += static_cast<char>(prover_is_server);
  return digest(input, EVP_sha512());
}

void check_evidence(const Evidence &evidence, std::string_view expected_reportdata, std::string_view expected_image) {
  require(expected_reportdata.size() == 64 && evidence.reportdata == expected_reportdata,
          "Fresh quote REPORTDATA does not match this session");
  require(evidence.image_hash_hex.size() == 64 && evidence.image_hash_hex == expected_image,
          "Quote image does not match signed membership");
  // v1 supports ordinary non-debug/non-migratable guests. Unknown/profiling/partitioning attributes fail closed.
  constexpr std::uint64_t allowed_attributes = (1ULL << 28) | (1ULL << 30) | (1ULL << 31);
  require((evidence.td_attributes & ~allowed_attributes) == 0 && !evidence.has_service_td,
          "Debug, migration, service-TD, or unsupported TDX attributes are forbidden");
}

AdmittedSession::AdmittedSession(const Member &peer, const Membership &membership, bool server, std::string key,
    std::function<void(std::string_view, std::function<void()>)> synchronize)
    : peer_(peer), membership_(membership), server_(server), probe_key_(std::move(key)), synchronize_(std::move(synchronize)) {}
AdmittedSession::~AdmittedSession() { OPENSSL_cleanse(probe_key_.data(), probe_key_.size()); }
void AdmittedSession::synchronize(std::string_view label, std::function<void()> progress) const {
  synchronize_(label, std::move(progress));
}

std::string admit_connected_socket(int socket, bool server, const Config &config, const Identity &identity,
                                   std::string_view signed_membership, std::string_view peer_node,
                                   EvidenceProvider &provider, const Deadline &deadline,
                                   const AfterAdmission &after_admission) {
  ErrorQueueGuard error_queue;
  deadline.check();
  auto membership = verify_membership(config, identity, signed_membership, wall_time());
  const auto &local_member = member(membership, config.node_id);
  const auto &remote_member = member(membership, peer_node);
  require(peer_node != config.node_id, "Cannot admit the local node as a peer");
  require((fcntl(socket, F_GETFL) & O_NONBLOCK) != 0, "Admission socket must be nonblocking");
  auto certificate = read_public_file(config.cert_base_name + "_cert.pem");
  auto private_key = read_private_file(config.cert_base_name + "_key.pem");
  TeeCertAndKey cert_and_key(certificate, private_key);
  OPENSSL_cleanse(private_key.data(), private_key.size());
  std::string verification_error;
  std::optional<Evidence> peer_certificate_evidence;
  std::string verified_certificate;
  auto handshake_deadline = deadline.within(std::chrono::seconds(config.timeouts.handshake_seconds));
  SslOptions options;
  options.mode = server ? SslOptions::Mode::Server : SslOptions::Mode::Client;
  options.cert_and_key = std::move(cert_and_key);
  options.custom_verify = [&](int preverified, void *context) {
    try {
      auto store = static_cast<X509_STORE_CTX *>(context);
      require(X509_STORE_CTX_get_error_depth(store) == 0, "Admission certificate chains are forbidden");
      auto error = X509_STORE_CTX_get_error(store);
      require(preverified || error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
                  error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, "Invalid TLS certificate");
      auto cert = X509_STORE_CTX_get_current_cert(store);
      std::array<unsigned char, 32> fingerprint{};
      unsigned size = 0;
      require(cert && X509_digest(cert, EVP_sha256(), fingerprint.data(), &size) == 1 && size == 32,
              "Cannot hash peer certificate");
      std::string hash(reinterpret_cast<const char *>(fingerprint.data()), fingerprint.size());
      if (!peer_certificate_evidence || hash != verified_certificate) {
        peer_certificate_evidence = verify_certificate(cert, config, provider, handshake_deadline);
        verified_certificate = hash;
      }
      return 1;
    } catch (const std::exception &error) { verification_error = error.what(); return 0; }
  };
  auto result = create_ssl_ctx(std::move(options));
  require(result.is_ok(), "Cannot load admission TLS certificate/key");
  auto context = result.move_as_ok();
  auto ctx = static_cast<SSL_CTX *>(context.get());
  SSL_CTX_set_max_cert_list(ctx, 65536);
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_num_tickets(ctx, 0);
  auto local_evidence = verify_certificate(SSL_CTX_get0_certificate(ctx), config, provider, deadline);
  require(local_evidence.image_hash_hex == local_member.image_hash_hex,
          "Local TLS image differs from signed membership");
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx), SSL_free);
  require(ssl && SSL_set_fd(ssl.get(), socket) == 1, "Cannot create admission TLS session");
  if (server) SSL_set_accept_state(ssl.get()); else SSL_set_connect_state(ssl.get());
  Session handshake(ssl.get(), socket, handshake_deadline);
  try { handshake.handshake(); }
  catch (...) { if (!verification_error.empty()) throw Error(verification_error); throw; }
  require(peer_certificate_evidence && peer_certificate_evidence->image_hash_hex == remote_member.image_hash_hex,
          "Peer TLS image differs from signed membership");
  auto local_tls_key = tls_key(SSL_get_certificate(ssl.get()));
  std::unique_ptr<X509, decltype(&X509_free)> remote_cert(SSL_get1_peer_certificate(ssl.get()), X509_free);
  auto remote_tls_key = tls_key(remote_cert.get());
  require(local_tls_key != remote_tls_key, "Admission peers must have distinct TLS identities");
  std::string binding(32, '\0');
  require(SSL_export_keying_material(ssl.get(), reinterpret_cast<unsigned char *>(binding.data()), binding.size(),
                                     exporter_label, sizeof(exporter_label) - 1, nullptr, 0, 0) == 1,
          "Cannot bind admission to this TLS connection");
  std::string nonce(32, '\0');
  require(RAND_priv_bytes(reinterpret_cast<unsigned char *>(nonce.data()), static_cast<int>(nonce.size())) == 1,
          "Cannot generate fresh admission challenge");
  auto membership_hash = digest(encode_membership(membership), EVP_sha256());
  Session session(ssl.get(), socket, deadline);
  std::string remote_nonce;
  if (server) {
    remote_nonce = parse_hello(session.receive(1), peer_node, membership_hash);
    session.send(1, hello(config.node_id, nonce, membership_hash));
  } else {
    session.send(1, hello(config.node_id, nonce, membership_hash));
    remote_nonce = parse_hello(session.receive(1), peer_node, membership_hash);
  }
  auto record = admission_record(membership, server ? peer_node : config.node_id,
                                  server ? config.node_id : peer_node, server ? remote_nonce : nonce,
                                  server ? nonce : remote_nonce, server ? remote_tls_key : local_tls_key,
                                  server ? local_tls_key : remote_tls_key, binding);
  std::string peer_quote;
  auto verify_peer = [&] {
    auto evidence = provider.verify(peer_quote, deadline);
    check_evidence(evidence, admission_reportdata(record, !server), remote_member.image_hash_hex);
    deadline.check();
    verify_membership(config, identity, signed_membership, wall_time());
  };
  if (server) {
    peer_quote = session.receive(2);
    verify_peer();
    session.send(2, provider.quote(admission_reportdata(record, true), deadline));
  } else {
    session.send(2, provider.quote(admission_reportdata(record, false), deadline));
    peer_quote = session.receive(2);
    verify_peer();
  }
  auto acceptance = digest(record, EVP_sha256());
  if (server) {
    require(session.receive(3) == acceptance, "Peer did not accept this admission context");
    session.send(3, acceptance);
  } else {
    session.send(3, acceptance);
    require(session.receive(3) == acceptance, "Peer did not accept this admission context");
  }
  deadline.check();
  verify_membership(config, identity, signed_membership, wall_time());
  if (after_admission) {
    constexpr char probe_label[] = "EXPERIMENTAL-cocoon-wg-probe-v1";
    std::string key(32, '\0');
    require(SSL_export_keying_material(ssl.get(), reinterpret_cast<unsigned char *>(key.data()), key.size(),
        probe_label, sizeof(probe_label) - 1, reinterpret_cast<const unsigned char *>(acceptance.data()),
        acceptance.size(), 1) == 1, "Cannot derive overlay probe key");
    AdmittedSession admitted(remote_member, membership, server, std::move(key), [&](std::string_view label,
                                                                      std::function<void()> progress) {
      require(!label.empty() && label.size() <= 64, "Invalid setup barrier label");
      deadline.check();
      verify_membership(config, identity, signed_membership, wall_time());
      auto proof = digest(acceptance + std::string("cocoon/wg-setup/v1\0", 19) + std::string(label), EVP_sha256());
      Session barrier(ssl.get(), socket, deadline, std::move(progress));
      if (server) {
        require(barrier.receive(4) == proof, "Peer setup barrier does not match");
        barrier.send(4, proof);
      } else {
        barrier.send(4, proof);
        require(barrier.receive(4) == proof, "Peer setup barrier does not match");
      }
      verify_membership(config, identity, signed_membership, wall_time());
    });
    after_admission(admitted);
    deadline.check();
    verify_membership(config, identity, signed_membership, wall_time());
  }
  return nlohmann::json{{"format", "cocoon-wireguard-admission-v1"}, {"status", "peer_admitted"},
                        {"workload_ready", false}, {"peer_node_id", remote_member.node_id},
                        {"peer_boot_id", remote_member.boot_id}, {"peer_overlay_ipv4", remote_member.overlay_ipv4},
                        {"peer_wireguard_public_key_b64", remote_member.wireguard_public_key_b64},
                        {"peer_tls_public_key_b64", base64(remote_tls_key)},
                        {"peer_image_hash_hex", remote_member.image_hash_hex},
                        {"peer_evidence_sha256", hex(digest(peer_quote, EVP_sha256()))},
                        {"membership_sha256", hex(membership_hash)}, {"transcript_sha256", hex(acceptance)},
                        {"generation", membership.generation}, {"expires_at", membership.expires_at}}
             .dump(2) + "\n";
}

std::string admit_peer(const Config &config, const Identity &identity, std::string_view signed_membership,
                       std::string_view peer_node, std::function<bool()> cancelled,
                       const AfterAdmission &after_admission, std::function<void()> progress) {
  auto provider = real_evidence_provider();
  auto peer = std::find_if(config.peers.begin(), config.peers.end(),
                            [&](const auto &p) { return p.node_id == peer_node; });
  require(peer != config.peers.end(), "Peer is not configured");
  verify_membership(config, identity, signed_membership, wall_time());
  Deadline deadline(Deadline::Clock::now() + std::chrono::seconds(config.timeouts.startup_seconds),
                    std::move(cancelled), std::move(progress));
  bool server = config.node_rank > peer->node_rank;
  auto socket = server ? accept_peer(config.admission_port, deadline) : connect_peer(*peer, deadline);
  return admit_connected_socket(socket.value, server, config, identity, signed_membership, peer_node,
                                 *provider, deadline, after_admission);
}

}  // namespace cocoon::wireguard
