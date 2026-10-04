#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cocoon::wireguard {

class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct Peer {
  std::string node_id;
  std::uint16_t node_rank{};
  std::string overlay_ipv4;
  std::string endpoint_ipv4;
  std::uint16_t endpoint_port{};
  std::uint16_t admission_endpoint_port{};
  bool required{true};
};

struct Timeouts {
  std::uint32_t startup_seconds{60};
  std::uint32_t handshake_seconds{15};
  std::uint32_t lease_seconds{300};
  std::uint32_t renewal_seconds{60};
  std::uint32_t peer_seconds{30};
};

enum class ImagePolicy { PinnedHashes, SignedMembership };

struct Config {
  std::string interface;
  std::string overlay_network;
  std::string cluster_id;
  std::string workload_policy_sha256;
  std::uint64_t generation{};
  std::string node_id;
  std::uint16_t node_rank{};
  std::string overlay_ipv4;
  std::uint16_t listen_port{};
  std::uint16_t admission_port{};
  std::string cert_base_name;
  std::string membership_signer_public_key_b64;
  std::vector<std::string> allowed_image_hashes_hex;
  ImagePolicy image_policy{ImagePolicy::PinnedHashes};
  std::uint16_t mtu{1400};
  std::uint16_t keepalive_seconds{25};
  Timeouts timeouts;
  std::vector<Peer> peers;
  bool fake_tee{false};
};

// Public enrollment material only. Attestation and key possession are checked in the admission step.
struct Identity {
  std::string boot_id;
  std::string wireguard_public_key_b64;
};

struct Member {
  std::string node_id;
  std::uint16_t node_rank{};
  std::string boot_id;
  std::string overlay_ipv4;
  std::string wireguard_public_key_b64;
  std::string image_hash_hex;
};

struct Membership {
  std::string cluster_id;
  std::string workload_policy_sha256;
  std::uint64_t generation{};
  std::uint64_t not_before{};
  std::uint64_t expires_at{};
  std::vector<Member> members;
  bool fake_tee{false};
};

// All parsers reject unknown/duplicate fields, noncanonical values, and oversized inputs.
Config parse_config(std::string_view json);
Membership parse_membership_payload(std::string_view json);
std::string membership_payload_json(const Membership &membership);

// Fixed, domain-separated binary encoding; JSON formatting is never signed.
std::string encode_membership(const Membership &membership);
Membership decode_membership(std::string_view payload);
std::string sign_membership(const Membership &membership, std::string_view ed25519_private_key_pem);
Membership verify_membership(const Config &config, const Identity &local_identity, std::string_view envelope,
                             std::uint64_t now);

std::string enrollment_json(const Config &config, const Identity &identity);
std::string identity_context(const Config &config);
Identity load_or_create_identity(const Config &config, const std::string &state_dir);

std::string read_public_file(const std::string &path);
std::string read_private_file(const std::string &path);
void write_public_file(const std::string &path, std::string_view content);

// Raw X25519 private bytes in, canonical WireGuard public key out. No private bytes are exported.
std::string derive_wireguard_public_key(std::string_view private_key);

}  // namespace cocoon::wireguard
