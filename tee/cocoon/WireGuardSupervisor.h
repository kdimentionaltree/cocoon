#pragma once

#include "WireGuardDevice.h"

namespace cocoon::wireguard {

struct HeartbeatDatagram { std::string node_id; std::string bytes; };

class LeaseSupervisor {
 public:
  using Clock = Deadline::Clock;
  LeaseSupervisor(const Config &config, const Membership &membership, Clock::time_point now, std::uint64_t wall);
  ~LeaseSupervisor();
  LeaseSupervisor(const LeaseSupervisor &) = delete;
  // Input has already passed verify_membership. Extension requires unchanged identities and increasing expiry.
  bool update_membership(const Membership &membership, Clock::time_point now, std::uint64_t wall);
  void authorize(const AdmittedSession &session, Clock::time_point now, std::uint64_t wall);
  void reject(std::string_view node_id, std::string reason);
  std::vector<HeartbeatDatagram> heartbeat_requests(Clock::time_point now, std::uint64_t wall, bool configured);
  std::string receive_heartbeat(std::string_view node_id, std::string_view packet, Clock::time_point now,
                                std::uint64_t wall, bool configured);
  bool ready(Clock::time_point now, std::uint64_t wall) const;
  void check(Clock::time_point now, std::uint64_t wall, bool was_ready) const;
  std::vector<WorkloadPermit> permits(Clock::time_point now, std::uint64_t wall) const;
  std::vector<std::string> expired_optional(Clock::time_point now, std::uint64_t wall) const;
  Clock::time_point group_until(Clock::time_point now, std::uint64_t wall) const;
  std::string status(std::string_view phase, bool ready, Clock::time_point now, std::uint64_t wall,
                     std::string_view reason = {}) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class ServiceNotifier {
 public:
  ServiceNotifier();
  ~ServiceNotifier();
  void notify(std::string_view message);
  void watchdog(Deadline::Clock::time_point now);
 private:
  int socket_{-1};
  bool watchdog_enabled_{};
  std::chrono::microseconds interval_{std::chrono::seconds(1)};
  Deadline::Clock::time_point next_{};
};

void run_overlay(const Config &config, const std::string &state_dir, const std::string &membership_path,
                 std::function<bool()> cancelled, std::function<void(std::string_view)> report);

}  // namespace cocoon::wireguard
