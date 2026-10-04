#pragma once

#include "WireGuardEnrollment.h"

#include <chrono>
#include <functional>
#include <memory>

namespace cocoon::wireguard {

class Deadline {
 public:
  using Clock = std::chrono::steady_clock;
  Deadline(Clock::time_point end, std::function<bool()> cancelled = {}, std::function<void()> progress = {});
  void check() const;
  void wait(int fd, short events) const;
  Clock::time_point end() const;
  Deadline within(std::chrono::seconds duration) const;

 private:
  Clock::time_point end_;
  std::function<bool()> cancelled_;
  std::function<void()> progress_;
};

struct Evidence {
  std::string reportdata;  // Exactly 64 raw bytes, verified by DCAP.
  std::string image_hash_hex;
  std::uint64_t td_attributes{};
  bool has_service_td{};
};

// Dependency injection is for isolated tests. The CLI always selects the real TDX provider.
class EvidenceProvider {
 public:
  virtual ~EvidenceProvider() = default;
  virtual std::string quote(std::string_view reportdata, const Deadline &deadline) = 0;
  virtual Evidence verify(std::string_view quote, const Deadline &deadline) = 0;
};

bool admission_supported();
std::unique_ptr<EvidenceProvider> real_evidence_provider();
int evidence_worker_main(std::string_view operation);
// Runs only this executable's fixed internal evidence operations; kills and reaps on timeout/cancellation.
std::string run_evidence_worker(std::string_view operation, std::string_view input, const Deadline &deadline);

// Deterministic binary transcript; both participants reconstruct it from trusted membership.
std::string admission_record(const Membership &membership, std::string_view client_node,
                             std::string_view server_node, std::string_view client_nonce,
                             std::string_view server_nonce, std::string_view client_tls_key,
                             std::string_view server_tls_key, std::string_view channel_binding);
std::string admission_reportdata(std::string_view record, bool prover_is_server);
void check_evidence(const Evidence &evidence, std::string_view expected_reportdata,
                    std::string_view expected_image);

// Exists only inside a freshly verified, still-owned TLS session. It cannot be reconstructed from JSON.
class AdmittedSession {
 public:
  AdmittedSession(const AdmittedSession &) = delete;
  const Member &peer() const { return peer_; }
  const Membership &membership() const { return membership_; }
  bool server() const { return server_; }
  std::string_view probe_key() const { return probe_key_; }
  // Both participants must use the same label. progress keeps UDP probes responsive during the barrier.
  void synchronize(std::string_view label, std::function<void()> progress = {}) const;

 private:
  friend std::string admit_connected_socket(int, bool, const Config &, const Identity &, std::string_view,
      std::string_view, EvidenceProvider &, const Deadline &, const std::function<void(const AdmittedSession &)> &);
  AdmittedSession(const Member &peer, const Membership &membership, bool server, std::string key,
                  std::function<void(std::string_view, std::function<void()>)> synchronize);
  ~AdmittedSession();
  const Member &peer_;
  const Membership &membership_;
  bool server_;
  std::string probe_key_;
  std::function<void(std::string_view, std::function<void()>)> synchronize_;
};
using AfterAdmission = std::function<void(const AdmittedSession &)>;

// Borrows a connected nonblocking socket; all TLS/session state remains owned until return/exception.
// A successful result records admission only. It is never workload readiness or a reusable admission grant.
std::string admit_connected_socket(int socket, bool server, const Config &config, const Identity &identity,
                                   std::string_view signed_membership, std::string_view peer_node,
                                   EvidenceProvider &provider, const Deadline &deadline,
                                   const AfterAdmission &after_admission = {});
std::string admit_peer(const Config &config, const Identity &identity, std::string_view signed_membership,
                       std::string_view peer_node, std::function<bool()> cancelled = {},
                       const AfterAdmission &after_admission = {}, std::function<void()> progress = {});

}  // namespace cocoon::wireguard
