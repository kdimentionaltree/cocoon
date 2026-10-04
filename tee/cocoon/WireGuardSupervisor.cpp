#include "WireGuardSupervisor.h"

#include <algorithm>
#include <array>
#include <deque>
#include <ctime>
#include <cstring>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

namespace cocoon::wireguard {
namespace {
using Clock = Deadline::Clock;
using Json = nlohmann::json;
constexpr char heartbeat_domain[] = "CWGH1";
constexpr std::size_t packet_size = sizeof(heartbeat_domain) + 3 + 64 + 32;
void require(bool ok, const char *message) { if (!ok) throw Error(message); }
std::string digest(std::string_view data) {
  std::array<unsigned char, 32> out{}; unsigned length = 0;
  require(EVP_Digest(data.data(), data.size(), out.data(), &length, EVP_sha256(), nullptr) == 1 && length == 32,
          "Cannot hash supervisor membership");
  return {reinterpret_cast<const char *>(out.data()), out.size()};
}
std::string mac(std::string_view key, std::string_view data) {
  std::array<unsigned char, 32> out{}; unsigned length = 0;
  require(key.size() == 32 && HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
      reinterpret_cast<const unsigned char *>(data.data()), data.size(), out.data(), &length) && length == 32,
      "Cannot authenticate heartbeat");
  return {reinterpret_cast<const char *>(out.data()), out.size()};
}
bool same_members(Membership a, Membership b) {
  a.not_before = b.not_before = 1; a.expires_at = b.expires_at = 2;
  return encode_membership(a) == encode_membership(b);
}
Clock::time_point lease_end(const Membership &membership, Clock::time_point now, std::uint64_t wall) {
  require(wall >= membership.not_before && wall < membership.expires_at, "Supervisor membership is outside its lease");
  return now + std::chrono::seconds(membership.expires_at - wall);
}
std::string hex(std::string_view data) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out; for (unsigned char c : data) { out += digits[c >> 4]; out += digits[c & 15]; } return out;
}
}  // namespace

struct LeaseSupervisor::Impl {
  struct PeerState {
    struct Challenge { std::string nonce; Clock::time_point issued; };
    Member member;
    std::string key;
    bool server{}, authorized{}, peer_configured{};
    Clock::time_point until{}, last_seen{}, next_send{};
    std::uint64_t expires_at{};
    std::deque<Challenge> challenges;
    std::string reason;
    ~PeerState() { OPENSSL_cleanse(key.data(), key.size()); }
  };
  Config config;
  Membership membership;
  std::string membership_hash;
  Clock::time_point membership_until;
  std::map<std::string, PeerState> peers;
  Impl(const Config &c, const Membership &m, Clock::time_point now, std::uint64_t wall)
      : config(c), membership(m), membership_hash(digest(encode_membership(m))), membership_until(lease_end(m, now, wall)) {
    for (const auto &peer : c.peers) peers.try_emplace(peer.node_id);
  }
  Clock::time_point peer_until(const PeerState &peer, Clock::time_point now, std::uint64_t wall) const {
    if (!peer.authorized || wall >= peer.expires_at) return now;
    return std::min({peer.until, now + std::chrono::seconds(peer.expires_at - wall),
                     peer.last_seen + std::chrono::seconds(config.timeouts.peer_seconds)});
  }
  bool healthy(const PeerState &peer, Clock::time_point now, std::uint64_t wall) const {
    return peer.authorized && peer_configured(peer) && peer_until(peer, now, wall) > now;
  }
  static bool peer_configured(const PeerState &peer) { return peer.peer_configured; }
  std::string packet(const PeerState &peer, unsigned char type, std::string_view nonce,
                     std::string_view echo, bool configured) const {
    std::string out(heartbeat_domain, sizeof(heartbeat_domain));
    out += static_cast<char>(peer.server); out += static_cast<char>(type); out += static_cast<char>(configured);
    out += nonce; out += echo; out += mac(peer.key, out); return out;
  }
};

LeaseSupervisor::LeaseSupervisor(const Config &config, const Membership &membership, Clock::time_point now, std::uint64_t wall)
    : impl_(std::make_unique<Impl>(config, membership, now, wall)) {}
LeaseSupervisor::~LeaseSupervisor() = default;
bool LeaseSupervisor::update_membership(const Membership &membership, Clock::time_point now, std::uint64_t wall) {
  auto hash = digest(encode_membership(membership));
  if (hash == impl_->membership_hash) return false;  // Never extend a monotonic deadline by rereading the same grant.
  require(same_members(membership, impl_->membership), "Renewal changed group, generation, or enrolled identities; restart required");
  require(membership.expires_at > impl_->membership.expires_at && membership.not_before >= impl_->membership.not_before,
          "Renewal rolled back the membership lease");
  auto end = lease_end(membership, now, wall);
  impl_->membership = membership; impl_->membership_hash = std::move(hash); impl_->membership_until = end;
  return true;
}
void LeaseSupervisor::authorize(const AdmittedSession &session, Clock::time_point now, std::uint64_t wall) {
  require(digest(encode_membership(session.membership())) == impl_->membership_hash,
          "Live admission does not match current supervisor membership");
  require(now < impl_->membership_until && wall < impl_->membership.expires_at, "Admission completed after lease expiry");
  auto found = impl_->peers.find(session.peer().node_id);
  require(found != impl_->peers.end(), "Admission peer is not supervised");
  auto &peer = found->second;
  OPENSSL_cleanse(peer.key.data(), peer.key.size());
  peer.key = mac(session.probe_key(), std::string("cocoon/wg-heartbeat-key/v1\0", 27));
  peer.member = session.peer(); peer.server = session.server(); peer.authorized = true;
  peer.until = impl_->membership_until; peer.expires_at = impl_->membership.expires_at;
  peer.last_seen = now; peer.next_send = {}; peer.challenges.clear(); peer.reason.clear();
}
void LeaseSupervisor::reject(std::string_view node_id, std::string reason) {
  auto found = impl_->peers.find(std::string(node_id)); require(found != impl_->peers.end(), "Unknown supervised peer");
  auto &peer = found->second;
  OPENSSL_cleanse(peer.key.data(), peer.key.size()); peer.key.clear(); peer.challenges.clear();
  peer.authorized = false; peer.peer_configured = false; peer.reason = std::move(reason);
}
std::vector<HeartbeatDatagram> LeaseSupervisor::heartbeat_requests(Clock::time_point now, std::uint64_t wall, bool configured) {
  std::vector<HeartbeatDatagram> out;
  for (auto &[node, peer] : impl_->peers) {
    if (!peer.authorized || now >= peer.until || wall >= peer.expires_at || now < peer.next_send) continue;
    std::string challenge(32, '\0');
    require(RAND_priv_bytes(reinterpret_cast<unsigned char *>(challenge.data()), 32) == 1, "Cannot challenge overlay peer");
    peer.challenges.push_back({challenge, now});
    if (peer.challenges.size() > 4) peer.challenges.pop_front();
    out.push_back({node, impl_->packet(peer, 1, challenge, std::string(32, '\0'), configured)});
    peer.next_send = now + std::chrono::seconds(1);
  }
  return out;
}
std::string LeaseSupervisor::receive_heartbeat(std::string_view node_id, std::string_view packet,
    Clock::time_point now, std::uint64_t wall, bool configured) {
  auto found = impl_->peers.find(std::string(node_id));
  if (found == impl_->peers.end() || packet.size() != packet_size) return {};
  auto &peer = found->second;
  if (!peer.authorized || now >= peer.until || wall >= peer.expires_at) return {};
  auto data = packet.substr(0, packet_size - 32), tag = packet.substr(packet_size - 32);
  auto expected = mac(peer.key, data);
  if (std::memcmp(data.data(), heartbeat_domain, sizeof(heartbeat_domain)) != 0 ||
      static_cast<unsigned char>(data[6]) != static_cast<unsigned char>(!peer.server) ||
      static_cast<unsigned char>(data[8]) > 1 || CRYPTO_memcmp(tag.data(), expected.data(), 32) != 0) return {};
  auto nonce = data.substr(9, 32), echo = data.substr(41, 32);
  if (data[7] == 1 && nonce != std::string(32, '\0') && echo == std::string(32, '\0')) {
    return impl_->packet(peer, 2, std::string(32, '\0'), nonce, configured);
  }
  if (data[7] != 2 || nonce != std::string(32, '\0')) return {};
  auto challenge = std::find_if(peer.challenges.begin(), peer.challenges.end(),
      [&](const auto &candidate) { return candidate.nonce == echo; });
  if (challenge != peer.challenges.end()) {
    // Use challenge issuance, so delaying an old valid response cannot extend the liveness deadline.
    if (challenge->issued >= peer.last_seen) {
      peer.last_seen = challenge->issued; peer.peer_configured = data[8] != 0;
    }
    peer.challenges.erase(challenge);  // An acknowledgment can refresh liveness only once.
  }
  return {};
}
bool LeaseSupervisor::ready(Clock::time_point now, std::uint64_t wall) const {
  if (now >= impl_->membership_until || wall >= impl_->membership.expires_at) return false;
  for (const auto &peer : impl_->config.peers) if (peer.required && !impl_->healthy(impl_->peers.at(peer.node_id), now, wall)) return false;
  return std::any_of(impl_->peers.begin(), impl_->peers.end(),
      [&](const auto &peer) { return impl_->healthy(peer.second, now, wall); });
}
void LeaseSupervisor::check(Clock::time_point now, std::uint64_t wall, bool was_ready) const {
  require(now < impl_->membership_until && wall < impl_->membership.expires_at, "Operator membership lease expired");
  if (was_ready) require(ready(now, wall), "Required peer lost authorization, liveness, or group readiness");
}
std::vector<WorkloadPermit> LeaseSupervisor::permits(Clock::time_point now, std::uint64_t wall) const {
  std::vector<WorkloadPermit> out;
  for (const auto &peer : impl_->config.peers) {
    const auto &state = impl_->peers.at(peer.node_id);
    if (impl_->healthy(state, now, wall)) out.push_back({peer.node_id, impl_->peer_until(state, now, wall)});
  }
  return out;
}
std::vector<std::string> LeaseSupervisor::expired_optional(Clock::time_point now, std::uint64_t wall) const {
  std::vector<std::string> out;
  for (const auto &peer : impl_->config.peers) {
    const auto &state = impl_->peers.at(peer.node_id);
    if (!peer.required && state.authorized && impl_->peer_until(state, now, wall) <= now) out.push_back(peer.node_id);
  }
  return out;
}
Clock::time_point LeaseSupervisor::group_until(Clock::time_point now, std::uint64_t wall) const {
  if (!ready(now, wall)) return now;
  auto end = std::min(impl_->membership_until, now + std::chrono::seconds(impl_->membership.expires_at - wall));
  for (const auto &peer : impl_->config.peers) if (peer.required) {
    end = std::min(end, impl_->peer_until(impl_->peers.at(peer.node_id), now, wall));
  }
  return end;
}
std::string LeaseSupervisor::status(std::string_view phase, bool ready, Clock::time_point now, std::uint64_t wall,
                                    std::string_view reason) const {
  Json peers = Json::array();
  for (const auto &config : impl_->config.peers) {
    const auto &peer = impl_->peers.at(config.node_id);
    auto end = impl_->peer_until(peer, now, wall);
    peers.push_back({{"node_id", config.node_id}, {"required", config.required}, {"overlay_ipv4", config.overlay_ipv4},
        {"state", peer.authorized ? (end > now ? (peer.peer_configured ? "healthy" : "awaiting_group") : "expired") : "not_admitted"},
        {"boot_id", peer.member.boot_id}, {"wireguard_public_key_b64", peer.member.wireguard_public_key_b64},
        {"image_hash_hex", peer.member.image_hash_hex}, {"expires_at", peer.expires_at}, {"rejection_reason", peer.reason},
        {"heartbeat_age_ms", peer.authorized ? Json(std::max<std::int64_t>(0,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.last_seen).count())) : Json(nullptr)},
        {"lease_remaining_ms", std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::milliseconds>(end - now).count())}});
  }
  return Json{{"format", "cocoon-wireguard-status-v1"}, {"state", phase}, {"workload_ready", ready},
      {"interface", impl_->config.interface}, {"overlay_ipv4", impl_->config.overlay_ipv4},
      {"generation", impl_->membership.generation}, {"expires_at", impl_->membership.expires_at},
      {"updated_at", wall}, {"membership_sha256", hex(impl_->membership_hash)}, {"rejection_reason", reason}, {"peers", peers}}.dump(2) + "\n";
}
}  // namespace cocoon::wireguard
