#pragma once

#include "WireGuardEnrollment.h"

namespace cocoon::wireguard {

// Holds the enrollment lock for the entire device lifetime. The sealed key descriptor is never public output.
class RuntimeIdentity {
 public:
  RuntimeIdentity(const Config &config, const std::string &state_dir, bool create_if_missing = true);
  ~RuntimeIdentity();
  RuntimeIdentity(const RuntimeIdentity &) = delete;
  RuntimeIdentity &operator=(const RuntimeIdentity &) = delete;
  const Identity &identity() const { return identity_; }
  int key_fd() const { return key_fd_; }

 private:
  Identity identity_;
  int lock_fd_{-1};
  int key_fd_{-1};
};

// Atomic, owner-only public diagnostics in the protected runtime directory; never follows a status symlink.
void write_runtime_status(const std::string &state_dir, std::string_view content);

}  // namespace cocoon::wireguard
