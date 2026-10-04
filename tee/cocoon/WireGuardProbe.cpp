#include "WireGuardDevice.h"

#include <array>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace cocoon::wireguard {
namespace {
constexpr char domain[] = "CWGP1";
void require(bool ok, const char *message) { if (!ok) throw Error(message); }
struct Socket {
  int fd;
  ~Socket() { if (fd >= 0) close(fd); }
};
sockaddr_in address(std::string_view ip) {
  sockaddr_in out{};
  out.sin_family = AF_INET;
  out.sin_port = htons(overlay_probe_port);
  require(inet_pton(AF_INET, std::string(ip).c_str(), &out.sin_addr) == 1, "Invalid overlay probe address");
  return out;
}
std::string mac(std::string_view key, std::string_view data) {
  require(key.size() == 32, "Invalid overlay probe session key");
  std::array<unsigned char, 32> out{};
  unsigned size = 0;
  require(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
      reinterpret_cast<const unsigned char *>(data.data()), data.size(), out.data(), &size) && size == out.size(),
      "Cannot authenticate overlay probe");
  return {reinterpret_cast<const char *>(out.data()), out.size()};
}

class Probe {
 public:
  Probe(int fd, const AdmittedSession &session, const Deadline &deadline, std::uint16_t mtu)
      : fd_(fd), session_(session), deadline_(deadline), packet_size_(mtu - 28U) {
    require(mtu >= 1280 && mtu <= 1420, "Invalid overlay probe MTU");
    require(RAND_priv_bytes(reinterpret_cast<unsigned char *>(nonce_.data()), static_cast<int>(nonce_.size())) == 1,
            "Cannot generate overlay probe challenge");
  }
  void tick() {
    deadline_.check();
    auto now = Deadline::Clock::now();
    if (now >= next_send_) {
      send(1, std::string(32, '\0'));
      next_send_ = now + std::chrono::milliseconds(100);
    }
    // Bound each iteration even if a peer floods malformed datagrams.
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
      deadline_.check();
      std::array<char, 1421> buffer{};
      auto n = recv(fd_, buffer.data(), buffer.size(), MSG_DONTWAIT);
      if (n < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED || errno == ENETUNREACH ||
            errno == EHOSTUNREACH) break;
        throw Error("Overlay probe receive failed");
      }
      if (n != static_cast<ssize_t>(packet_size_)) continue;
      std::string_view packet(buffer.data(), packet_size_);
      auto data = packet.substr(0, packet_size_ - 32);
      auto tag = mac(session_.probe_key(), data);
      if (std::memcmp(packet.data(), domain, sizeof(domain)) != 0 ||
          static_cast<unsigned char>(packet[sizeof(domain)]) != static_cast<unsigned char>(!session_.server()) ||
          CRYPTO_memcmp(packet.data() + packet_size_ - 32, tag.data(), 32) != 0) continue;
      auto type = packet[sizeof(domain) + 1];
      auto remote_nonce = packet.substr(sizeof(domain) + 2, 32);
      auto echo = packet.substr(sizeof(domain) + 34, 32);
      if (remote_nonce == std::string(32, '\0')) continue;
      if (type == 1 && echo == std::string(32, '\0')) send(2, remote_nonce);
      if (type == 2 && CRYPTO_memcmp(echo.data(), nonce_.data(), nonce_.size()) == 0) verified_ = true;
    }
  }
  bool verified() const { return verified_; }

 private:
  void send(char type, std::string_view echo) {
    std::string packet(domain, sizeof(domain));
    packet += static_cast<char>(session_.server());
    packet += type;
    packet.append(nonce_.data(), nonce_.size());
    packet += echo;
    packet.resize(packet_size_ - 32, '\0');
    packet += mac(session_.probe_key(), packet);
    auto n = ::send(fd_, packet.data(), packet.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    // A fresh WireGuard handshake or an initially unreachable peer may temporarily reject sends.
    require(n == static_cast<ssize_t>(packet.size()) || (n < 0 && (errno == EINTR || errno == EAGAIN ||
        errno == ECONNREFUSED || errno == ENETUNREACH || errno == EHOSTUNREACH || errno == ENOKEY)),
        "Overlay probe send failed");
  }
  int fd_;
  const AdmittedSession &session_;
  const Deadline &deadline_;
  std::array<char, 32> nonce_{};
  Deadline::Clock::time_point next_send_{};
  bool verified_{};
  std::size_t packet_size_;
};
}  // namespace

void probe_overlay(const Config &config, const AdmittedSession &session, const Deadline &deadline) {
  Socket socket{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  require(socket.fd >= 0, "Cannot open overlay probe socket");
  require(setsockopt(socket.fd, SOL_SOCKET, SO_BINDTODEVICE, config.interface.c_str(),
      static_cast<socklen_t>(config.interface.size() + 1)) == 0, "Cannot bind probe to WireGuard device");
  int dont_fragment = IP_PMTUDISC_DO;
  require(setsockopt(socket.fd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_fragment, sizeof(dont_fragment)) == 0,
          "Cannot require an unfragmented overlay probe");
  auto local = address(config.overlay_ipv4), remote = address(session.peer().overlay_ipv4);
  // No SO_REUSEADDR/PORT: reserve the narrowly permitted control port while probing this pair.
  require(bind(socket.fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0 &&
              connect(socket.fd, reinterpret_cast<sockaddr *>(&remote), sizeof(remote)) == 0,
          "Cannot bind overlay probe endpoints");
  probe_connected_udp(socket.fd, session, deadline, config.mtu);
}

void probe_connected_udp(int socket, const AdmittedSession &session, const Deadline &deadline, std::uint16_t mtu) {
  require(socket >= 0, "Invalid overlay probe socket");
  Probe probe(socket, session, deadline, mtu);
  while (!probe.verified()) {
    probe.tick();
    if (!probe.verified()) deadline.wait(-1, 0);
  }
  // Continue acknowledging retransmissions while the other participant proves its receive path.
  session.synchronize("overlay-probed", [&] { probe.tick(); });
  deadline.check();
}
}  // namespace cocoon::wireguard
