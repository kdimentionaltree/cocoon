#pragma once

#include "WireGuardAdmission.h"
#include "WireGuardRuntimeIdentity.h"
#include <map>

namespace cocoon::wireguard {

inline constexpr std::uint16_t overlay_probe_port = 51822;
inline constexpr std::uint16_t overlay_heartbeat_port = 51823;
struct WorkloadPermit {
  std::string node_id;
  Deadline::Clock::time_point until;
};
enum class NetworkTool { Ip, WireGuard, Nftables };

// Test injection is confined to library callers. The CLI always uses fixed guest executables.
class NetworkCommands {
 public:
  virtual ~NetworkCommands() = default;
  virtual std::string run(NetworkTool tool, const std::vector<std::string> &arguments,
                          std::string_view input, int key_fd, const Deadline &deadline) = 0;
};
std::unique_ptr<NetworkCommands> real_network_commands();

class WireGuardDevice {
 public:
  WireGuardDevice(const Config &config, NetworkCommands &commands);
  ~WireGuardDevice();
  WireGuardDevice(const WireGuardDevice &) = delete;
  void start(const RuntimeIdentity &identity, const Deadline &deadline);
  // Accepts only a live admission capability; never a saved public admission result.
  void install_peer(const AdmittedSession &session, const Deadline &deadline);
  void remove_peer(std::string_view node_id, const Deadline &deadline);
  void check_inventory(const Deadline &deadline);
  // Timed kernel permissions must never outlive the supervisor's lease/liveness deadlines.
  bool update_workload(const std::vector<WorkloadPermit> &peers, Deadline::Clock::time_point group_until,
                       const Deadline &deadline);
  void close_workload(const Deadline &deadline);
  // Deletes only the interface created by this instance, including its routes and kernel peers.
  // The independently installed firewall remains closed, including after cleanup.
  void stop(const Deadline &deadline);

 private:
  Config config_;
  NetworkCommands &commands_;
  bool owns_interface_{};
  std::string ownership_alias_;
  std::vector<std::string> installed_peers_;
  std::map<std::string, std::string> installed_keys_;
  bool guard_installed_{};
  std::string command(NetworkTool tool, std::vector<std::string> arguments, const Deadline &deadline,
                      std::string_view input = {}, int key_fd = -1);
};

void install_closed_guard(const Config &config, NetworkCommands &commands, const Deadline &deadline);
void cleanup_overlay(const Config &config, const std::string &state_dir, NetworkCommands &commands,
                     const Deadline &deadline);

// Both directions must prove possession of the fresh TLS exporter key through device-bound UDP sockets.
void probe_overlay(const Config &config, const AdmittedSession &session, const Deadline &deadline);
// Borrows a connected nonblocking UDP socket. Production callers use probe_overlay to enforce device binding.
void probe_connected_udp(int socket, const AdmittedSession &session, const Deadline &deadline, std::uint16_t mtu);

// Sets up the configured mesh, reports connectivity with workload_ready:false, and holds it only until
// cancellation/lease expiry. Continuous renewal, workload activation and systemd notification are step 4.
void setup_overlay(const Config &config, const std::string &state_dir, std::string_view signed_membership,
                   std::function<bool()> cancelled, std::function<void(std::string_view)> report);

}  // namespace cocoon::wireguard
