#include "WireGuardEnrollment.h"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <set>

#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace cocoon::wireguard {
namespace {

using Json = nlohmann::json;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
constexpr std::size_t max_json_size = 65536;
constexpr std::size_t max_members = 64;
constexpr char membership_domain[] = "cocoon/wg-membership/v1";

void require(bool ok, const std::string &message) {
  if (!ok) {
    throw Error(message);
  }
}

Json parse_json(std::string_view input) {
  require(!input.empty() && input.size() <= max_json_size, "JSON document size is out of bounds");
  std::vector<std::set<std::string>> objects;
  try {
    return Json::parse(input, [&](int depth, Json::parse_event_t event, Json &value) {
      require(depth <= 16, "JSON nesting is too deep");
      if (event == Json::parse_event_t::object_start) {
        objects.emplace_back();
      } else if (event == Json::parse_event_t::key) {
        require(!objects.empty() && objects.back().insert(value.get<std::string>()).second,
                "Duplicate JSON field");
      } else if (event == Json::parse_event_t::object_end) {
        objects.pop_back();
      }
      return true;
    });
  } catch (const Json::exception &) {
    throw Error("Invalid JSON document");
  }
}

void fields(const Json &object, std::initializer_list<std::string_view> required,
            std::initializer_list<std::string_view> optional = {}) {
  require(object.is_object(), "Expected a JSON object");
  for (auto field : required) {
    require(object.contains(std::string(field)), "Missing required field: " + std::string(field));
  }
  for (auto it = object.begin(); it != object.end(); ++it) {
    auto has = [&](auto list) { return std::find(list.begin(), list.end(), it.key()) != list.end(); };
    require(has(required) || has(optional), "Unknown JSON field");
  }
}

std::string text(const Json &object, const char *field, std::size_t max_size = 4096) {
  const auto &value = object.at(field);
  require(value.is_string(), std::string(field) + " must be a string");
  auto result = value.get<std::string>();
  require(!result.empty() && result.size() <= max_size, std::string(field) + " length is out of bounds");
  return result;
}

std::uint64_t number(const Json &object, const char *field, std::uint64_t min, std::uint64_t max) {
  const auto &value = object.at(field);
  require(value.is_number_integer(), std::string(field) + " must be an integer");
  if (!value.is_number_unsigned()) {
    require(value.get<std::int64_t>() >= 0, std::string(field) + " must be nonnegative");
  }
  auto result = value.get<std::uint64_t>();
  require(result >= min && result <= max, std::string(field) + " is out of bounds");
  return result;
}

void identifier(std::string_view value) {
  require(!value.empty() && value.size() <= 64, "Identifier length is out of bounds");
  for (auto c : value) {
    require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_',
            "Identifiers must contain only ASCII letters, digits, hyphens, or underscores");
  }
}

std::string hex_bytes(std::string_view value, std::size_t size) {
  require(value.size() == size * 2, "Invalid hexadecimal length");
  std::string result(size, '\0');
  auto nibble = [](char c) -> unsigned {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    require(c >= 'a' && c <= 'f', "Hexadecimal values must be lowercase and canonical");
    return c - 'a' + 10;
  };
  for (std::size_t i = 0; i < size; ++i) {
    result[i] = static_cast<char>((nibble(value[i * 2]) << 4) | nibble(value[i * 2 + 1]));
  }
  return result;
}

std::string to_hex(std::string_view value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (unsigned char c : value) {
    result += digits[c >> 4];
    result += digits[c & 15];
  }
  return result;
}

std::string base64(std::string_view value) {
  std::string result(4 * ((value.size() + 2) / 3), '\0');
  auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                             reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
  require(size >= 0 && static_cast<std::size_t>(size) == result.size(), "Base64 encoding failed");
  return result;
}

std::string unbase64(std::string_view value, std::size_t exact_size = 0) {
  require(!value.empty() && value.size() <= max_json_size && value.size() % 4 == 0, "Invalid base64 length");
  std::string result(value.size() / 4 * 3, '\0');
  auto size = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                             reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
  require(size >= 0, "Invalid base64 value");
  std::size_t padding = (value.back() == '=') + (value.size() > 1 && value[value.size() - 2] == '=');
  require(static_cast<std::size_t>(size) >= padding, "Invalid base64 padding");
  result.resize(size - padding);
  require(base64(result) == value && (!exact_size || result.size() == exact_size), "Noncanonical base64 or wrong size");
  return result;
}

void public_key(std::string_view key) {
  auto raw = unbase64(key, 32);
  require(raw != std::string(32, '\0'), "Public key must not be zero");
}

std::uint32_t ipv4(std::string_view value) {
  in_addr address{};
  require(inet_pton(AF_INET, std::string(value).c_str(), &address) == 1, "Invalid IPv4 address");
  char canonical[INET_ADDRSTRLEN];
  require(inet_ntop(AF_INET, &address, canonical, sizeof(canonical)) && value == canonical,
          "Noncanonical IPv4 address");
  auto ip = ntohl(address.s_addr);
  require((ip >> 24) != 0 && (ip >> 24) != 127 && (ip >> 24) < 224, "IPv4 address must be unicast and non-loopback");
  return ip;
}

bool private_ip(std::uint32_t ip) {
  return (ip >> 24) == 10 || (ip >> 20) == 0xac1 || (ip >> 16) == 0xc0a8;
}

struct Network {
  std::uint32_t address;
  std::uint32_t mask;
  bool contains(std::uint32_t ip) const {
    return (ip & mask) == address;
  }
  void host(std::uint32_t ip) const {
    require(contains(ip) && ip != address && ip != (address | ~mask), "Overlay address is outside the usable subnet");
  }
};

Network network(std::string_view value) {
  auto slash = value.find('/');
  require(slash != std::string_view::npos, "Overlay network must use CIDR notation");
  auto suffix = value.substr(slash + 1);
  require(!suffix.empty() && suffix.size() <= 2 && suffix.front() != '0', "Invalid network prefix");
  unsigned prefix = 0;
  for (char c : suffix) {
    require(c >= '0' && c <= '9', "Invalid network prefix");
    prefix = prefix * 10 + c - '0';
  }
  require(prefix >= 8 && prefix <= 30, "Overlay prefix must be between /8 and /30");
  auto ip = ipv4(value.substr(0, slash));
  auto mask = std::numeric_limits<std::uint32_t>::max() << (32 - prefix);
  require((ip & mask) == ip && private_ip(ip) && private_ip(ip | ~mask), "Overlay must be a canonical RFC1918 subnet");
  return {ip, mask};
}

void absolute_path(std::string_view path) {
  require(path.size() > 1 && path.front() == '/' && path.back() != '/' && path.find('\0') == std::string_view::npos,
          "Path must be absolute and normalized");
  std::size_t start = 1;
  while (start < path.size()) {
    auto end = path.find('/', start);
    if (end == std::string_view::npos) {
      end = path.size();
    }
    auto part = path.substr(start, end - start);
    require(!part.empty() && part != "." && part != "..", "Path must be normalized");
    start = end + 1;
  }
}

void validate_membership(const Membership &m) {
  identifier(m.cluster_id);
  hex_bytes(m.workload_policy_sha256, 32);
  require(m.generation > 0 && m.generation <= INT64_MAX && m.not_before < m.expires_at && m.expires_at <= INT64_MAX,
          "Invalid membership validity");
  require(m.members.size() >= 2 && m.members.size() <= max_members, "Membership must have 2 to 64 members");
  std::set<std::string> nodes, ips, keys, boots;
  std::set<std::uint16_t> ranks;
  for (const auto &member : m.members) {
    identifier(member.node_id);
    hex_bytes(member.boot_id, 32);
    require(member.boot_id != std::string(64, '0'), "Boot identity must not be zero");
    require(private_ip(ipv4(member.overlay_ipv4)), "Overlay addresses must be RFC1918 addresses");
    public_key(member.wireguard_public_key_b64);
    hex_bytes(member.image_hash_hex, 32);
    require(member.node_rank < m.members.size(), "Member rank is outside the group");
    require(nodes.insert(member.node_id).second && ranks.insert(member.node_rank).second &&
                ips.insert(member.overlay_ipv4).second && keys.insert(member.wireguard_public_key_b64).second &&
                boots.insert(member.boot_id).second,
            "Duplicate member identity, rank, address, key, or boot identity");
  }
}

void integer(std::string &out, std::uint64_t value, unsigned width) {
  for (unsigned i = width; i > 0; --i) {
    out += static_cast<char>(value >> (8 * (i - 1)));
  }
}

void sized_text(std::string &out, std::string_view value) {
  integer(out, value.size(), 2);
  out.append(value);
}

struct Decoder {
  std::string_view input;
  std::string_view take(std::size_t size) {
    require(size <= input.size(), "Truncated membership payload");
    auto value = input.substr(0, size);
    input.remove_prefix(size);
    return value;
  }
  std::uint64_t integer(unsigned width) {
    std::uint64_t value = 0;
    for (unsigned char c : take(width)) {
      value = (value << 8) | c;
    }
    return value;
  }
  std::string text() {
    auto size = integer(2);
    require(size > 0 && size <= 64, "Identifier length is out of bounds");
    return std::string(take(size));
  }
};

Json payload_json(const Membership &m) {
  Json members = Json::array();
  for (const auto &member : m.members) {
    members.push_back({{"node_id", member.node_id}, {"node_rank", member.node_rank},
                       {"boot_id", member.boot_id}, {"overlay_ipv4", member.overlay_ipv4},
                       {"wireguard_public_key_b64", member.wireguard_public_key_b64},
                       {"image_hash_hex", member.image_hash_hex}, {"tee_type", "tdx"}});
  }
  return {{"format", "cocoon-wireguard-membership-v1"}, {"cluster_id", m.cluster_id},
          {"workload_policy_sha256", m.workload_policy_sha256}, {"generation", m.generation},
          {"not_before", m.not_before}, {"expires_at", m.expires_at}, {"members", members}};
}

}  // namespace

Config parse_config(std::string_view input) {
  auto j = parse_json(input);
  fields(j, {"format", "interface", "overlay_network", "cluster_id", "workload_policy_sha256", "generation",
             "node_id", "node_rank", "overlay_ipv4", "listen_port", "admission_port", "cert_base_name",
             "membership_signer_public_key_b64", "attestation", "peers"},
         {"mtu", "keepalive_seconds", "timeouts"});
  require(text(j, "format") == "cocoon-wireguard-config-v1", "Unsupported configuration format");
  Config c;
  c.interface = text(j, "interface");
  identifier(c.interface);
  require(c.interface.size() <= 15 && c.interface.starts_with("wg"), "Interface must start with wg and fit IFNAMSIZ");
  c.overlay_network = text(j, "overlay_network");
  auto subnet = network(c.overlay_network);
  c.cluster_id = text(j, "cluster_id");
  identifier(c.cluster_id);
  c.workload_policy_sha256 = text(j, "workload_policy_sha256");
  hex_bytes(c.workload_policy_sha256, 32);
  c.generation = number(j, "generation", 1, INT64_MAX);
  c.node_id = text(j, "node_id");
  identifier(c.node_id);
  c.node_rank = static_cast<std::uint16_t>(number(j, "node_rank", 0, max_members - 1));
  c.overlay_ipv4 = text(j, "overlay_ipv4");
  subnet.host(ipv4(c.overlay_ipv4));
  c.listen_port = static_cast<std::uint16_t>(number(j, "listen_port", 1024, 65535));
  c.admission_port = static_cast<std::uint16_t>(number(j, "admission_port", 1024, 65535));
  c.cert_base_name = text(j, "cert_base_name");
  absolute_path(c.cert_base_name);
  c.membership_signer_public_key_b64 = text(j, "membership_signer_public_key_b64");
  public_key(c.membership_signer_public_key_b64);
  const auto &policy = j.at("attestation");
  fields(policy, {"type", "allowed_image_hashes_hex"});
  require(text(policy, "type") == "tdx", "Only real TDX admission is supported");
  const auto &images = policy.at("allowed_image_hashes_hex");
  require(images.is_array() && !images.empty() && images.size() <= max_members,
          "Image allowlist must be nonempty and bounded");
  std::set<std::string> distinct_images;
  for (const auto &image : images) {
    require(image.is_string(), "Image hash must be a string");
    auto hash = image.get<std::string>();
    hex_bytes(hash, 32);
    require(distinct_images.insert(hash).second, "Duplicate image hash");
    c.allowed_image_hashes_hex.push_back(hash);
  }
  if (j.contains("mtu")) {
    c.mtu = static_cast<std::uint16_t>(number(j, "mtu", 1280, 1420));
  }
  if (j.contains("keepalive_seconds")) {
    c.keepalive_seconds = static_cast<std::uint16_t>(number(j, "keepalive_seconds", 0, 120));
  }
  if (j.contains("timeouts")) {
    const auto &t = j.at("timeouts");
    fields(t, {"startup_seconds", "handshake_seconds", "lease_seconds", "renewal_seconds", "peer_seconds"});
    c.timeouts.startup_seconds = static_cast<std::uint32_t>(number(t, "startup_seconds", 1, 3600));
    c.timeouts.handshake_seconds = static_cast<std::uint32_t>(number(t, "handshake_seconds", 1, 300));
    c.timeouts.lease_seconds = static_cast<std::uint32_t>(number(t, "lease_seconds", 10, 3600));
    c.timeouts.renewal_seconds = static_cast<std::uint32_t>(number(t, "renewal_seconds", 1, 1800));
    c.timeouts.peer_seconds = static_cast<std::uint32_t>(number(t, "peer_seconds", 1, 300));
  }
  require(c.timeouts.handshake_seconds <= c.timeouts.startup_seconds &&
              c.timeouts.renewal_seconds < c.timeouts.lease_seconds &&
              c.timeouts.peer_seconds < c.timeouts.lease_seconds,
          "Inconsistent timeout and lease settings");
  const auto &peers = j.at("peers");
  require(peers.is_array() && !peers.empty() && peers.size() < max_members, "Configure 1 to 63 peers");
  std::set<std::string> nodes{c.node_id}, addresses{c.overlay_ipv4};
  std::set<std::uint16_t> ranks{c.node_rank};
  std::set<std::pair<std::string, std::uint16_t>> udp_endpoints, tcp_endpoints;
  for (const auto &p : peers) {
    fields(p, {"node_id", "node_rank", "overlay_ipv4", "endpoint_ipv4", "endpoint_port", "admission_endpoint_port"},
           {"required"});
    Peer peer;
    peer.node_id = text(p, "node_id");
    identifier(peer.node_id);
    peer.node_rank = static_cast<std::uint16_t>(number(p, "node_rank", 0, peers.size()));
    peer.overlay_ipv4 = text(p, "overlay_ipv4");
    subnet.host(ipv4(peer.overlay_ipv4));
    peer.endpoint_ipv4 = text(p, "endpoint_ipv4");
    require(!subnet.contains(ipv4(peer.endpoint_ipv4)), "Underlay endpoint overlaps the overlay route");
    peer.endpoint_port = static_cast<std::uint16_t>(number(p, "endpoint_port", 1024, 65535));
    peer.admission_endpoint_port = static_cast<std::uint16_t>(number(p, "admission_endpoint_port", 1024, 65535));
    if (p.contains("required")) {
      require(p.at("required").is_boolean(), "required must be boolean");
      peer.required = p.at("required").get<bool>();
    }
    require(nodes.insert(peer.node_id).second && ranks.insert(peer.node_rank).second &&
                addresses.insert(peer.overlay_ipv4).second,
            "Duplicate configured node, rank, or overlay address");
    require(udp_endpoints.emplace(peer.endpoint_ipv4, peer.endpoint_port).second &&
                tcp_endpoints.emplace(peer.endpoint_ipv4, peer.admission_endpoint_port).second,
            "Duplicate peer transport endpoint");
    c.peers.push_back(std::move(peer));
  }
  require(c.node_rank <= c.peers.size(), "Local rank is outside the group");
  return c;
}

Membership parse_membership_payload(std::string_view input) {
  auto j = parse_json(input);
  fields(j, {"format", "cluster_id", "workload_policy_sha256", "generation", "not_before", "expires_at", "members"});
  require(text(j, "format") == "cocoon-wireguard-membership-v1", "Unsupported membership format");
  Membership m;
  m.cluster_id = text(j, "cluster_id");
  m.workload_policy_sha256 = text(j, "workload_policy_sha256");
  m.generation = number(j, "generation", 1, INT64_MAX);
  m.not_before = number(j, "not_before", 0, INT64_MAX);
  m.expires_at = number(j, "expires_at", 1, INT64_MAX);
  const auto &members = j.at("members");
  require(members.is_array() && members.size() >= 2 && members.size() <= max_members,
          "Membership must have 2 to 64 members");
  for (const auto &member : members) {
    fields(member, {"node_id", "node_rank", "boot_id", "overlay_ipv4", "wireguard_public_key_b64",
                    "image_hash_hex", "tee_type"});
    require(text(member, "tee_type") == "tdx", "Only TDX members are supported");
    m.members.push_back({text(member, "node_id"),
                         static_cast<std::uint16_t>(number(member, "node_rank", 0, max_members - 1)),
                         text(member, "boot_id"), text(member, "overlay_ipv4"),
                         text(member, "wireguard_public_key_b64"),
                         text(member, "image_hash_hex")});
  }
  validate_membership(m);
  return m;
}

std::string encode_membership(const Membership &membership) {
  validate_membership(membership);
  auto members = membership.members;
  std::sort(members.begin(), members.end(), [](const auto &a, const auto &b) { return a.node_id < b.node_id; });
  std::string out(membership_domain, sizeof(membership_domain));
  sized_text(out, membership.cluster_id);
  out += hex_bytes(membership.workload_policy_sha256, 32);
  integer(out, membership.generation, 8);
  integer(out, membership.not_before, 8);
  integer(out, membership.expires_at, 8);
  integer(out, members.size(), 2);
  for (const auto &m : members) {
    sized_text(out, m.node_id);
    integer(out, m.node_rank, 2);
    out += hex_bytes(m.boot_id, 32);
    integer(out, ipv4(m.overlay_ipv4), 4);
    out += unbase64(m.wireguard_public_key_b64, 32);
    out += hex_bytes(m.image_hash_hex, 32);
  }
  return out;
}

Membership decode_membership(std::string_view payload) {
  require(payload.size() <= max_json_size, "Membership payload is too large");
  Decoder d{payload};
  require(d.take(sizeof(membership_domain)) == std::string_view(membership_domain, sizeof(membership_domain)),
          "Unsupported membership payload domain");
  Membership m;
  m.cluster_id = d.text();
  m.workload_policy_sha256 = to_hex(d.take(32));
  m.generation = d.integer(8);
  m.not_before = d.integer(8);
  m.expires_at = d.integer(8);
  auto count = d.integer(2);
  require(count >= 2 && count <= max_members, "Membership member count is out of bounds");
  for (std::size_t i = 0; i < count; ++i) {
    Member member;
    member.node_id = d.text();
    member.node_rank = static_cast<std::uint16_t>(d.integer(2));
    member.boot_id = to_hex(d.take(32));
    auto ip = static_cast<std::uint32_t>(d.integer(4));
    in_addr address{htonl(ip)};
    char rendered[INET_ADDRSTRLEN];
    require(inet_ntop(AF_INET, &address, rendered, sizeof(rendered)), "Invalid encoded IPv4 address");
    member.overlay_ipv4 = rendered;
    member.wireguard_public_key_b64 = base64(d.take(32));
    member.image_hash_hex = to_hex(d.take(32));
    m.members.push_back(std::move(member));
  }
  require(d.input.empty(), "Trailing membership bytes");
  require(encode_membership(m) == payload, "Noncanonical membership encoding");
  return m;
}

std::string membership_payload_json(const Membership &m) {
  validate_membership(m);
  return payload_json(m).dump(2) + "\n";
}

std::string sign_membership(const Membership &membership, std::string_view pem) {
  require(!pem.empty() && pem.size() <= 16384, "Signing key size is out of bounds");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
  require(static_cast<bool>(bio), "Could not read signing key");
  auto no_password = [](char *, int, int, void *) { return 0; };
  Key key(PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr), EVP_PKEY_free);
  require(key && EVP_PKEY_base_id(key.get()) == EVP_PKEY_ED25519,
          "Signing key must be an unencrypted Ed25519 PEM key");
  auto encoded = encode_membership(membership);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(ctx && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1,
          "Signature initialization failed");
  std::array<unsigned char, 64> signature{};
  std::size_t size = signature.size();
  require(EVP_DigestSign(ctx.get(), signature.data(), &size, reinterpret_cast<const unsigned char *>(encoded.data()),
                         encoded.size()) == 1 && size == signature.size(),
          "Membership signing failed");
  std::array<unsigned char, 32> pub{};
  size = pub.size();
  require(EVP_PKEY_get_raw_public_key(key.get(), pub.data(), &size) == 1 && size == pub.size(),
          "Signing public key extraction failed");
  return Json{{"format", "cocoon-wireguard-signed-membership-v1"}, {"payload_b64", base64(encoded)},
              {"signature_b64", base64({reinterpret_cast<const char *>(signature.data()), signature.size()})},
              {"signer_public_key_b64", base64({reinterpret_cast<const char *>(pub.data()), pub.size()})}}
             .dump(2) + "\n";
}

Membership verify_membership(const Config &config, const Identity &identity, std::string_view input,
                             std::uint64_t now) {
  auto j = parse_json(input);
  fields(j, {"format", "payload_b64", "signature_b64", "signer_public_key_b64"});
  require(text(j, "format") == "cocoon-wireguard-signed-membership-v1", "Unsupported signature envelope");
  require(text(j, "signer_public_key_b64") == config.membership_signer_public_key_b64,
          "Membership signer is not trusted");
  auto raw_key = unbase64(config.membership_signer_public_key_b64, 32);
  auto encoded = unbase64(text(j, "payload_b64", max_json_size));
  auto signature = unbase64(text(j, "signature_b64"), 64);
  Key key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                     reinterpret_cast<const unsigned char *>(raw_key.data()), raw_key.size()),
          EVP_PKEY_free);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1,
          "Verification initialization failed");
  require(EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                          reinterpret_cast<const unsigned char *>(encoded.data()), encoded.size()) == 1,
          "Invalid membership signature");
  auto m = decode_membership(encoded);
  require(m.cluster_id == config.cluster_id && m.workload_policy_sha256 == config.workload_policy_sha256 &&
              m.generation == config.generation,
          "Membership cluster, workload, or generation does not match configuration");
  require(m.not_before <= now && now < m.expires_at && m.expires_at - m.not_before <= config.timeouts.lease_seconds,
          "Membership is not currently valid or exceeds the configured lease");
  require(m.members.size() == config.peers.size() + 1, "Membership does not match the configured group");
  bool found_local = false;
  for (const auto &member : m.members) {
    require(std::find(config.allowed_image_hashes_hex.begin(), config.allowed_image_hashes_hex.end(),
                      member.image_hash_hex) != config.allowed_image_hashes_hex.end(),
            "Member image is not authorized by policy");
    if (member.node_id == config.node_id) {
      require(member.node_rank == config.node_rank && member.overlay_ipv4 == config.overlay_ipv4 &&
                  member.boot_id == identity.boot_id &&
                  member.wireguard_public_key_b64 == identity.wireguard_public_key_b64,
              "Local membership does not match this guest's enrolled identity");
      found_local = true;
    } else {
      auto peer = std::find_if(config.peers.begin(), config.peers.end(),
                               [&](const auto &p) { return p.node_id == member.node_id; });
      require(peer != config.peers.end() && peer->node_rank == member.node_rank &&
                  peer->overlay_ipv4 == member.overlay_ipv4,
              "Member is outside the configured peer allocation");
    }
  }
  require(found_local, "Local member is missing");
  return m;
}

std::string identity_context(const Config &c) {
  std::string out("cocoon/wg-identity/v1\0", 22);
  sized_text(out, c.cluster_id);
  sized_text(out, c.node_id);
  integer(out, c.node_rank, 2);
  integer(out, ipv4(c.overlay_ipv4), 4);
  out += hex_bytes(c.workload_policy_sha256, 32);
  out += unbase64(c.membership_signer_public_key_b64, 32);
  return out;
}

std::string enrollment_json(const Config &c, const Identity &identity) {
  public_key(identity.wireguard_public_key_b64);
  hex_bytes(identity.boot_id, 32);
  return Json{{"format", "cocoon-wireguard-enrollment-v1"}, {"cluster_id", c.cluster_id},
              {"workload_policy_sha256", c.workload_policy_sha256}, {"generation", c.generation},
              {"node_id", c.node_id}, {"node_rank", c.node_rank}, {"boot_id", identity.boot_id},
              {"overlay_ipv4", c.overlay_ipv4}, {"wireguard_public_key_b64", identity.wireguard_public_key_b64},
              {"requested_tee_type", "tdx"}, {"attestation_status", "not_collected"}}
             .dump(2) + "\n";
}

std::string derive_wireguard_public_key(std::string_view private_key) {
  require(private_key.size() == 32, "WireGuard private key must be 32 bytes");
  Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                      reinterpret_cast<const unsigned char *>(private_key.data()),
                                      private_key.size()), EVP_PKEY_free);
  std::array<unsigned char, 32> pub{};
  std::size_t size = pub.size();
  require(key && EVP_PKEY_get_raw_public_key(key.get(), pub.data(), &size) == 1 && size == pub.size(),
          "WireGuard public key derivation failed");
  return base64({reinterpret_cast<const char *>(pub.data()), pub.size()});
}

}  // namespace cocoon::wireguard
