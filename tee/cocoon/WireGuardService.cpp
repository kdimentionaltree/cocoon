#include "WireGuardSupervisor.h"

#include <array>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <ctime>
#include <cstring>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace cocoon::wireguard {
namespace {
using Clock = Deadline::Clock;
void require(bool ok, const char *message) { if (!ok) throw Error(message); }
std::uint64_t wall_time() {
  auto time = std::time(nullptr); require(time >= 0, "Cannot read supervisor wall clock");
  return static_cast<std::uint64_t>(time);
}
std::uint64_t env_number(const char *name, std::uint64_t fallback) {
  auto value = std::getenv(name); if (!value) return fallback;
  std::uint64_t result = 0;
  auto end = value + std::strlen(value);
  auto parsed = std::from_chars(value, end, result);
  require(parsed.ec == std::errc() && parsed.ptr == end && value != end, "Invalid systemd watchdog environment");
  return result;
}
sockaddr_in address(std::string_view ip) {
  sockaddr_in out{}; out.sin_family = AF_INET; out.sin_port = htons(overlay_heartbeat_port);
  require(inet_pton(AF_INET, std::string(ip).c_str(), &out.sin_addr) == 1, "Invalid heartbeat address"); return out;
}
class Heartbeats {
 public:
  explicit Heartbeats(const Config &config) : config_(config) {
    socket_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(socket_ >= 0, "Cannot open heartbeat socket");
    try {
      require(setsockopt(socket_, SOL_SOCKET, SO_BINDTODEVICE, config.interface.c_str(),
          static_cast<socklen_t>(config.interface.size() + 1)) == 0, "Cannot bind heartbeats to WireGuard");
      auto local = address(config.overlay_ipv4);
      require(bind(socket_, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0, "Cannot reserve heartbeat control port");
    } catch (...) { close(socket_); socket_ = -1; throw; }
  }
  ~Heartbeats() { if (socket_ >= 0) close(socket_); }
  void tick(LeaseSupervisor &supervisor, Clock::time_point now, std::uint64_t wall, bool configured) {
    for (const auto &request : supervisor.heartbeat_requests(now, wall, configured)) send(request.node_id, request.bytes);
    for (unsigned i = 0; i < 128; ++i) {
      std::array<char, 512> buffer{};
      sockaddr_in remote{}; socklen_t length = sizeof(remote);
      auto n = recvfrom(socket_, buffer.data(), buffer.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&remote), &length);
      if (n < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        throw Error("Heartbeat receive failed");
      }
      if (remote.sin_family != AF_INET || remote.sin_port != htons(overlay_heartbeat_port)) continue;
      auto peer = std::find_if(config_.peers.begin(), config_.peers.end(), [&](const Peer &p) {
        return address(p.overlay_ipv4).sin_addr.s_addr == remote.sin_addr.s_addr;
      });
      if (peer == config_.peers.end()) continue;
      auto reply = supervisor.receive_heartbeat(peer->node_id, {buffer.data(), static_cast<std::size_t>(n)}, now, wall, configured);
      if (!reply.empty()) send(peer->node_id, reply);
    }
  }
 private:
  void send(std::string_view node, std::string_view packet) {
    auto peer = std::find_if(config_.peers.begin(), config_.peers.end(), [&](const Peer &p) { return p.node_id == node; });
    require(peer != config_.peers.end(), "Unknown heartbeat recipient");
    auto remote = address(peer->overlay_ipv4);
    auto n = sendto(socket_, packet.data(), packet.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
        reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
    require(n == static_cast<ssize_t>(packet.size()) || (n < 0 && (errno == EINTR || errno == EAGAIN ||
        errno == EHOSTUNREACH || errno == ENETUNREACH || errno == ECONNREFUSED || errno == ENOKEY)),
        "Heartbeat send failed");
  }
  Config config_; int socket_{-1};
};
}  // namespace

ServiceNotifier::ServiceNotifier() {
  auto path = std::getenv("NOTIFY_SOCKET");
  if (!path) return;
  sockaddr_un target{}; target.sun_family = AF_UNIX;
  auto length = std::strlen(path);
  require(length > 1 && length < sizeof(target.sun_path) && (path[0] == '/' || path[0] == '@'),
          "Invalid systemd notification socket");
  std::memcpy(target.sun_path, path, length);
  if (path[0] == '@') target.sun_path[0] = '\0';
  auto usec = env_number("WATCHDOG_USEC", 2000000);
  require(usec >= 200000 && usec <= 3600000000ULL, "Systemd watchdog interval is outside supported bounds");
  interval_ = std::chrono::microseconds(usec / 2);
  auto watchdog_pid = env_number("WATCHDOG_PID", static_cast<std::uint64_t>(getpid()));
  watchdog_enabled_ = std::getenv("WATCHDOG_USEC") && watchdog_pid == static_cast<std::uint64_t>(getpid());
  socket_ = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  require(socket_ >= 0, "Cannot open systemd notification socket");
  if (connect(socket_, reinterpret_cast<sockaddr *>(&target),
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + length + (path[0] == '@' ? 0 : 1))) != 0) {
    close(socket_); socket_ = -1; throw Error("Cannot connect to systemd notification socket");
  }
}
ServiceNotifier::~ServiceNotifier() { if (socket_ >= 0) close(socket_); }
void ServiceNotifier::notify(std::string_view message) {
  if (socket_ < 0) return;
  require(message.size() <= 4096 && send(socket_, message.data(), message.size(), MSG_DONTWAIT | MSG_NOSIGNAL) ==
      static_cast<ssize_t>(message.size()), "Systemd notification failed");
}
void ServiceNotifier::watchdog(Clock::time_point now) {
  if (watchdog_enabled_ && now >= next_) { notify("WATCHDOG=1"); next_ = now + interval_; }
}

void run_overlay(const Config &config, const std::string &state_dir, const std::string &membership_path,
                 std::function<bool()> cancelled, std::function<void(std::string_view)> report) {
  require(admission_supported(config), "This build has no real TDX/DCAP support; supervision is disabled");
  require(config.timeouts.peer_seconds >= 5, "Supervision requires peer_seconds >= 5 for kernel timeout margins");
  RuntimeIdentity identity(config, state_dir);
  ServiceNotifier notifier;
  auto envelope = read_public_file(membership_path);
  auto membership = verify_membership(config, identity.identity(), envelope, wall_time());
  auto initial_end = Clock::now() + std::chrono::seconds(config.timeouts.startup_seconds);
  LeaseSupervisor supervisor(config, membership, Clock::now(), wall_time());
  auto commands = real_network_commands();
  WireGuardDevice device(config, *commands);
  std::unique_ptr<Heartbeats> heartbeats;
  bool configured = false, announced_ready = false, in_tick = false, gate_open = false;
  std::string phase = "admitting";
  std::string last_report;
  auto next_gate = Clock::time_point{}, next_status = Clock::time_point{}, next_inventory = Clock::time_point{};
  auto publish = [&](std::string_view reason = {}) {
    auto status = supervisor.status(phase, gate_open, Clock::now(), wall_time(), reason);
    write_runtime_status(state_dir, status);
    auto event = phase + (gate_open ? ":ready:" : ":closed:") + std::string(reason);
    if (report && event != last_report) { report(status); last_report = std::move(event); }
  };
  auto pump = [&] {
    if (in_tick) return;
    struct TickGuard { bool &flag; ~TickGuard() { flag = false; } } guard{in_tick};
    in_tick = true;
    auto now = Clock::now(); auto wall = wall_time();
    if (heartbeats) heartbeats->tick(supervisor, now, wall, configured);
    supervisor.check(now, wall, announced_ready);
    for (const auto &node : supervisor.expired_optional(now, wall)) {
      supervisor.reject(node, "Optional peer lease or liveness expired");
      device.remove_peer(node, Deadline(Clock::now() + std::chrono::seconds(1)));
    }
    if (announced_ready && now >= next_inventory) {
      device.check_inventory(Deadline(now + std::chrono::seconds(1)));
      next_inventory = Clock::now() + std::chrono::seconds(1);
    }
    if (configured && supervisor.ready(now, wall) && now >= next_gate) {
      gate_open = device.update_workload(supervisor.permits(now, wall), supervisor.group_until(now, wall),
          Deadline(Clock::now() + std::chrono::seconds(1)));
      require(gate_open, "Authorization or liveness has reached the kernel permission cutoff");
      next_gate = Clock::now() + std::chrono::milliseconds(500);
      if (!announced_ready) {
        device.check_inventory(Deadline(Clock::now() + std::chrono::seconds(1)));
        phase = "ready"; publish(); notifier.notify("READY=1\nSTATUS=WireGuard overlay ready"); announced_ready = true;
      }
    }
    if (now >= next_status) { publish(); next_status = Clock::now() + std::chrono::seconds(1); }
    notifier.watchdog(Clock::now());
  };
  auto round = [&](Clock::time_point end) {
    Deadline startup(end, cancelled, pump);
    auto count = config.peers.size() + 1;
    for (std::size_t low = 0; low < count; ++low) for (std::size_t high = low + 1; high < count; ++high) {
      if (config.node_rank != low && config.node_rank != high) continue;
      auto rank = config.node_rank == low ? high : low;
      const auto &peer = *std::find_if(config.peers.begin(), config.peers.end(), [&](const Peer &p) { return p.node_rank == rank; });
      auto peer_end = peer.required ? end : std::min(end, Clock::now() + std::chrono::seconds(config.timeouts.handshake_seconds));
      try {
        startup.check();
        admit_peer(config, identity.identity(), envelope, peer.node_id,
            [&] { return (cancelled && cancelled()) || Clock::now() >= peer_end; },
            [&](const AdmittedSession &session) {
              device.install_peer(session, startup);
              session.synchronize("device-installed");
              probe_overlay(config, session, startup.within(std::chrono::seconds(config.timeouts.peer_seconds)));
              supervisor.authorize(session, Clock::now(), wall_time());
            }, pump);
      } catch (const std::exception &error) {
        supervisor.reject(peer.node_id, error.what());
        if (peer.required || (cancelled && cancelled())) throw;
        device.remove_peer(peer.node_id, Deadline(Clock::now() + std::chrono::seconds(5)));
      }
    }
  };
  try {
    publish();
    device.start(identity, Deadline(initial_end, cancelled));
    heartbeats = std::make_unique<Heartbeats>(config);
    round(initial_end); configured = true;
    Deadline ready_deadline(initial_end, cancelled, pump);
    while (!announced_ready) ready_deadline.wait(-1, 0);
    auto next_renew = Clock::now() + std::chrono::seconds(config.timeouts.renewal_seconds);
    for (;;) {
      Deadline(Clock::now() + std::chrono::seconds(1), cancelled, pump).check();
      auto latest = read_public_file(membership_path);
      auto grant = verify_membership(config, identity.identity(), latest, wall_time());
      if (supervisor.update_membership(grant, Clock::now(), wall_time()) || Clock::now() >= next_renew) {
        envelope = std::move(latest); phase = "renewing"; publish();
        round(Clock::now() + std::chrono::seconds(config.timeouts.startup_seconds)); phase = "ready"; publish();
        next_renew = Clock::now() + std::chrono::seconds(config.timeouts.renewal_seconds);
      }
      Deadline(Clock::now() + std::chrono::seconds(1), cancelled, pump).wait(-1, 0);
    }
  } catch (const std::exception &error) {
    auto reason = std::string(error.what());
    phase = "stopping"; gate_open = false;
    // No READY=0 protocol: fail the service and let BindsTo consumers stop. Close the gate before teardown.
    try { device.close_workload(Deadline(Clock::now() + std::chrono::seconds(5))); } catch (...) {}
    try { publish(reason); } catch (...) {}
    try { notifier.notify("STOPPING=1\nSTATUS=WireGuard overlay unavailable"); } catch (...) {}
    device.stop(Deadline(Clock::now() + std::chrono::seconds(5)));
    phase = "stopped"; publish(reason);
    if (cancelled && cancelled()) return;
    throw;
  }
}
}  // namespace cocoon::wireguard
