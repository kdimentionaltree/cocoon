#include "WireGuardEnrollment.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace wg = cocoon::wireguard;
using Json = nlohmann::json;

namespace {

unsigned assertions = 0;

void check(bool condition, const char *message) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(message);
  }
}

template <class F>
void rejected(F &&f) {
  ++assertions;
  try {
    f();
  } catch (const wg::Error &) {
    return;
  }
  throw std::runtime_error("Invalid input was accepted");
}

std::string from_hex(const std::string &hex) {
  std::string out;
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    out += static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }
  return out;
}

std::string base64(std::string_view raw) {
  std::string out(4 * ((raw.size() + 2) / 3), '\0');
  EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                  reinterpret_cast<const unsigned char *>(raw.data()), static_cast<int>(raw.size()));
  return out;
}

std::string unbase64(std::string_view value) {
  std::string out(value.size() / 4 * 3, '\0');
  auto size = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                              reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
  auto padding = (value.back() == '=') + (value[value.size() - 2] == '=');
  out.resize(size - padding);
  return out;
}

const std::string signer_public = base64(from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
const std::string alice_public = base64(from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
const std::string bob_public = base64(from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));

std::string signing_key(bool alternate = false) {
  auto seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  if (alternate) {
    seed[0] ^= 1;
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                   reinterpret_cast<const unsigned char *>(seed.data()), seed.size()),
      EVP_PKEY_free);
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  check(key && bio && PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
        "Could not prepare RFC 8032 signing key");
  char *data = nullptr;
  auto size = BIO_get_mem_data(bio.get(), &data);
  return std::string(data, size);
}

Json config_json() {
  return {{"format", "cocoon-wireguard-config-v1"}, {"interface", "wg0"}, {"overlay_network", "10.77.0.0/24"},
          {"cluster_id", "test-cluster"}, {"workload_policy_sha256", std::string(64, '1')}, {"generation", 7},
          {"node_id", "worker-a"}, {"node_rank", 0}, {"overlay_ipv4", "10.77.0.1"}, {"listen_port", 51820},
          {"admission_port", 51821}, {"cert_base_name", "/etc/tee/tee"},
          {"membership_signer_public_key_b64", signer_public},
          {"attestation", {{"type", "tdx"}, {"allowed_image_hashes_hex", Json::array({std::string(64, 'a')})}}},
          {"peers", Json::array({{{"node_id", "worker-b"}, {"node_rank", 1}, {"overlay_ipv4", "10.77.0.2"},
                                  {"endpoint_ipv4", "198.51.100.20"}, {"endpoint_port", 51820},
                                  {"admission_endpoint_port", 51821}}})}};
}

wg::Membership membership() {
  return {"test-cluster", std::string(64, '1'), 7, 1900, 2100,
          {{"worker-a", 0, std::string(64, '2'), "10.77.0.1", alice_public, std::string(64, 'a')},
           {"worker-b", 1, std::string(64, '3'), "10.77.0.2", bob_public, std::string(64, 'a')}}};
}

wg::Identity alice_identity() {
  return {std::string(64, '2'), alice_public};
}

struct TemporaryDirectory {
  std::string path;
  TemporaryDirectory() {
    std::array<char, 64> name{};
    std::string pattern = "/tmp/cocoon-wireguard-test-XXXXXX";
    std::copy(pattern.begin(), pattern.end(), name.begin());
    auto dir = mkdtemp(name.data());
    if (!dir) {
      throw std::runtime_error("Cannot create temporary test directory");
    }
    path = dir;
  }
  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

void configuration_tests() {
  auto valid = config_json();
  auto c = wg::parse_config(valid.dump());
  check(c.mtu == 1400 && c.keepalive_seconds == 25 && c.peers.size() == 1 && c.timeouts.lease_seconds == 300,
        "Incorrect configuration defaults");
  auto malformed = [&](const std::function<void(Json &)> &edit) {
    auto copy = valid;
    edit(copy);
    rejected([&] { wg::parse_config(copy.dump()); });
  };
  malformed([](auto &j) { j["unexpected"] = "ignored"; });
  malformed([](auto &j) { j.erase("cluster_id"); });
  malformed([](auto &j) { j["format"] = "unknown"; });
  malformed([](auto &j) { j["interface"] = "eth0"; });
  malformed([](auto &j) { j["interface"] = "wg;touch-pwned"; });
  malformed([](auto &j) { j["listen_port"] = 65536; });
  malformed([](auto &j) { j["listen_port"] = "51820"; });
  malformed([](auto &j) { j["generation"] = -1; });
  malformed([](auto &j) { j["generation"] = 1.0; });
  malformed([](auto &j) { j["node_rank"] = true; });
  malformed([](auto &j) { j["node_rank"] = 2; });
  malformed([](auto &j) { j["workload_policy_sha256"] = std::string(64, 'A'); });
  malformed([](auto &j) { j["overlay_network"] = "10.77.0.1/24"; });
  malformed([](auto &j) { j["overlay_network"] = "203.0.113.0/24"; });
  malformed([](auto &j) { j["overlay_network"] = "10.77.0.0/32"; });
  malformed([](auto &j) { j["overlay_ipv4"] = "10.77.0.255"; });
  malformed([](auto &j) { j["overlay_ipv4"] = "10.77.0.0"; });
  malformed([](auto &j) { j["overlay_ipv4"] = "10.77.1.1"; });
  malformed([](auto &j) { j["overlay_ipv4"] = "010.77.0.1"; });
  malformed([](auto &j) { j["peers"][0]["endpoint_ipv4"] = "10.77.0.2"; });
  malformed([](auto &j) { j["peers"][0]["node_id"] = "worker-a"; });
  malformed([](auto &j) { j["peers"][0]["node_rank"] = 0; });
  malformed([](auto &j) { j["peers"][0]["overlay_ipv4"] = "10.77.0.1"; });
  malformed([](auto &j) { j["peers"][0]["required"] = "yes"; });
  malformed([](auto &j) { j["attestation"]["type"] = "any"; });
  auto fake_config = valid;
  fake_config["attestation"]["type"] = "fake_tee";
  check(wg::parse_config(fake_config.dump()).fake_tee, "Explicit fake-TEE policy was rejected");
  fake_config["peers"][0]["endpoint_ipv4"] = "127.0.0.1";
  check(wg::parse_config(fake_config.dump()).peers[0].endpoint_ipv4 == "127.0.0.1",
        "Fake mode cannot test admission on loopback");
  malformed([](auto &j) { j["attestation"]["type"] = "sev"; });
  malformed([](auto &j) { j["attestation"]["allowed_image_hashes_hex"] = Json::array(); });
  malformed([](auto &j) { j["attestation"] = {{"type", "tdx"}, {"image_policy", "any"}}; });
  malformed([](auto &j) { j["attestation"]["image_policy"] = "signed_membership"; });
  auto signed_policy = valid;
  signed_policy["attestation"] = {{"type", "tdx"}, {"image_policy", "signed_membership"}};
  auto delegated = wg::parse_config(signed_policy.dump());
  check(delegated.image_policy == wg::ImagePolicy::SignedMembership && delegated.allowed_image_hashes_hex.empty(),
        "Signed image policy was not explicit or retained a circular allowlist");
  malformed([](auto &j) { j["membership_signer_public_key_b64"] = base64(std::string(32, '\0')); });
  malformed([](auto &j) { j["cert_base_name"] = "/etc/../tee"; });
  malformed([](auto &j) { j["cert_base_name"] = "relative"; });
  auto t = Json{{"startup_seconds", 60}, {"handshake_seconds", 15}, {"lease_seconds", 300},
                {"renewal_seconds", 300}, {"peer_seconds", 30}};
  malformed([&](auto &j) { j["timeouts"] = t; });
  auto raw = valid.dump();
  raw.insert(1, "\"node_id\":\"duplicate\",");
  rejected([&] { wg::parse_config(raw); });
  raw = valid.dump();
  auto pos = raw.find("\"type\":");
  raw.insert(pos, "\"ty\\u0070e\":\"any\",");
  rejected([&] { wg::parse_config(raw); });
  rejected([&] { wg::parse_config(std::string(65537, ' ')); });
  rejected([&] { wg::parse_config(valid.dump() + " {}"); });
  rejected([&] { wg::parse_config("{ malformed"); });
  rejected([&] { wg::parse_config("[]"); });
}

void membership_tests() {
  auto c = wg::parse_config(config_json().dump());
  auto m = membership();
  auto encoded = wg::encode_membership(m);
  check(encoded.substr(0, 24) == std::string("cocoon/wg-membership/v1\0", 24), "Missing signature domain separator");
  check(wg::encode_membership(wg::decode_membership(encoded)) == encoded, "Binary format did not round trip");
  auto reversed = m;
  std::reverse(reversed.members.begin(), reversed.members.end());
  check(wg::encode_membership(reversed) == encoded, "Member order affected canonical encoding");
  check(wg::encode_membership(wg::parse_membership_payload(wg::membership_payload_json(m))) == encoded,
        "JSON transport changed canonical payload");
  for (std::size_t i = 0; i < encoded.size(); ++i) {
    rejected([&] { wg::decode_membership(std::string_view(encoded).substr(0, i)); });
  }
  rejected([&] { wg::decode_membership(encoded + "trailing"); });
  auto envelope = wg::sign_membership(m, signing_key());
  check(Json::parse(envelope).at("signer_public_key_b64") == signer_public, "Signer differs from RFC 8032 vector");
  check(wg::verify_membership(c, alice_identity(), envelope, 2000).members.size() == 2, "Valid signature rejected");
  auto fake_config = c; fake_config.fake_tee = true;
  auto fake_membership = m; fake_membership.fake_tee = true;
  auto fake_envelope = wg::sign_membership(fake_membership, signing_key());
  check(wg::decode_membership(wg::encode_membership(fake_membership)).fake_tee,
        "Fake membership lost its signed mode");
  check(wg::encode_membership(fake_membership) != encoded, "Fake membership shared the real signing domain");
  check(wg::parse_membership_payload(wg::membership_payload_json(fake_membership)).fake_tee,
        "Fake membership JSON lost its mode");
  check(wg::verify_membership(fake_config, alice_identity(), fake_envelope, 2000).fake_tee,
        "Explicit fake membership rejected");
  rejected([&] { wg::verify_membership(c, alice_identity(), fake_envelope, 2000); });
  rejected([&] { wg::verify_membership(fake_config, alice_identity(), envelope, 2000); });
  auto mixed = Json::parse(wg::membership_payload_json(m));
  mixed["members"][0]["tee_type"] = "fake_tee";
  rejected([&] { wg::parse_membership_payload(mixed.dump()); });
  check(wg::identity_context(c) != wg::identity_context(fake_config), "Debug reused the real identity context");
  auto fake_offer = Json::parse(wg::enrollment_json(fake_config, alice_identity()));
  check(fake_offer["requested_tee_type"] == "fake_tee" && fake_offer["attestation_status"] == "synthetic",
        "Debug enrollment claimed hardware evidence");
  check(wg::verify_membership(c, alice_identity(), envelope, 1900).not_before == 1900,
        "Valid lower time boundary rejected");
  rejected([&] { wg::verify_membership(c, alice_identity(), envelope, 2100); });
  rejected([&] { wg::verify_membership(c, alice_identity(), envelope, 1899); });
  rejected([&] { wg::verify_membership(c, alice_identity(), wg::membership_payload_json(m), 2000); });
  rejected([&] { wg::verify_membership(c, alice_identity(), wg::sign_membership(m, signing_key(true)), 2000); });
  auto tampered = Json::parse(envelope);
  auto bytes = unbase64(tampered.at("payload_b64").get<std::string>());
  bytes.back() ^= 1;
  tampered["payload_b64"] = base64(bytes);
  rejected([&] { wg::verify_membership(c, alice_identity(), tampered.dump(), 2000); });
  tampered = Json::parse(envelope);
  tampered["signature_b64"] = base64(std::string(64, '\0'));
  rejected([&] { wg::verify_membership(c, alice_identity(), tampered.dump(), 2000); });
  auto bad = [&](const std::function<void(wg::Membership &)> &edit) {
    auto copy = m;
    edit(copy);
    rejected([&] { wg::verify_membership(c, alice_identity(), wg::sign_membership(copy, signing_key()), 2000); });
  };
  bad([](auto &v) { v.cluster_id = "other-cluster"; });
  bad([](auto &v) { v.workload_policy_sha256 = std::string(64, '4'); });
  bad([](auto &v) { v.generation = 6; });
  bad([](auto &v) { v.expires_at = 2300; });
  bad([](auto &v) { v.members[0].boot_id = std::string(64, '4'); });
  bad([](auto &v) { std::swap(v.members[0].wireguard_public_key_b64, v.members[1].wireguard_public_key_b64); });
  bad([](auto &v) { v.members[1].node_id = "unallocated-worker"; });
  bad([](auto &v) { v.members[1].overlay_ipv4 = "10.77.0.3"; });
  bad([](auto &v) { v.members[1].image_hash_hex = std::string(64, 'f'); });
  auto delegated = c;
  delegated.image_policy = wg::ImagePolicy::SignedMembership;
  delegated.allowed_image_hashes_hex.clear();
  auto approved = m; approved.members[1].image_hash_hex = std::string(64, 'f');
  auto approval = wg::sign_membership(approved, signing_key());
  check(wg::verify_membership(delegated, alice_identity(), approval, 2000).members[1].image_hash_hex == std::string(64, 'f'),
        "Operator-approved images still required embedding their own final spec hash");
  rejected([&] { wg::verify_membership(delegated, alice_identity(), wg::sign_membership(approved, signing_key(true)), 2000); });
  bad([](auto &v) { v.members[1].node_id = v.members[0].node_id; });
  bad([](auto &v) { v.members[1].node_rank = v.members[0].node_rank; });
  bad([](auto &v) { v.members[1].wireguard_public_key_b64 = v.members[0].wireguard_public_key_b64; });
  bad([](auto &v) { v.members[1].boot_id = v.members[0].boot_id; });
  bad([](auto &v) { v.members[1].overlay_ipv4 = v.members[0].overlay_ipv4; });
  auto public_json = Json::parse(wg::membership_payload_json(m));
  public_json["members"][0]["tee_type"] = "sev";
  rejected([&] { wg::parse_membership_payload(public_json.dump()); });
  // The signer field cannot substitute for the measured trust anchor, even with a valid alternative signature.
  auto other_signature = Json::parse(wg::sign_membership(m, signing_key(true)));
  other_signature["signer_public_key_b64"] = signer_public;
  rejected([&] { wg::verify_membership(c, alice_identity(), other_signature.dump(), 2000); });
}

void large_group_test() {
  auto j = config_json();
  auto m = membership();
  j["peers"] = Json::array();
  m.members.clear();
  for (unsigned i = 0; i < 64; ++i) {
    auto id = i == 0 ? "worker-a" : "worker-" + std::to_string(i);
    auto ip = "10.77.0." + std::to_string(i + 1);
    auto boot = std::string(62, '1') + "0123456789abcdef"[i >> 4] + "0123456789abcdef"[i & 15];
    auto key = wg::derive_wireguard_public_key(std::string(32, static_cast<char>(i + 1)));
    m.members.push_back({id, static_cast<std::uint16_t>(i), boot, ip, key, std::string(64, 'a')});
    if (i) {
      j["peers"].push_back({{"node_id", id}, {"node_rank", i}, {"overlay_ipv4", ip},
                             {"endpoint_ipv4", "203.0.113." + std::to_string(i)}, {"endpoint_port", 51820},
                             {"admission_endpoint_port", 51821}});
    }
  }
  auto c = wg::parse_config(j.dump());
  auto signature = wg::sign_membership(m, signing_key());
  wg::Identity local{m.members[0].boot_id, m.members[0].wireguard_public_key_b64};
  check(wg::verify_membership(c, local, signature, 2000).members.size() == 64,
        "Maximum-sized group failed verification");
}

void identity_tests() {
  auto alice_private = from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  check(wg::derive_wireguard_public_key(alice_private) == alice_public, "X25519 differs from RFC 7748 vector");
  auto c = wg::parse_config(config_json().dump());
  TemporaryDirectory temporary;
  auto dir = temporary.path + "/identity";
  auto first = wg::load_or_create_identity(c, dir);
  auto second = wg::load_or_create_identity(c, dir);
  check(first.boot_id == second.boot_id && first.wireguard_public_key_b64 == second.wireguard_public_key_b64,
        "Identity changed during a daemon restart");
  auto offer = Json::parse(wg::enrollment_json(c, first));
  check(offer.at("attestation_status") == "not_collected" && offer.at("requested_tee_type") == "tdx",
        "Export incorrectly claims verified attestation");
  check(!offer.contains("private_key") && !offer.contains("wireguard_private_key_b64") && offer.size() == 11,
        "Enrollment exported unexpected fields");
  struct stat s{};
  check(stat(dir.c_str(), &s) == 0 && (s.st_mode & 07777) == 0700 && s.st_uid == geteuid(), "Insecure state directory");
  auto state = dir + "/identity.bin";
  check(stat(state.c_str(), &s) == 0 && (s.st_mode & 07777) == 0600 && s.st_nlink == 1, "Insecure private identity");
  auto other = wg::load_or_create_identity(c, temporary.path + "/other");
  check(first.boot_id != other.boot_id && first.wireguard_public_key_b64 != other.wireguard_public_key_b64,
        "New identities were not independently generated");
  auto different = c;
  different.workload_policy_sha256 = std::string(64, '9');
  rejected([&] { wg::load_or_create_identity(different, dir); });
  different = c;
  ++different.generation;
  check(wg::load_or_create_identity(different, dir).boot_id == first.boot_id,
        "Membership renewal rotated the boot identity");
  chmod(state.c_str(), 0644);
  rejected([&] { wg::load_or_create_identity(c, dir); });
  chmod(state.c_str(), 0600);
  chmod(dir.c_str(), 0755);
  rejected([&] { wg::load_or_create_identity(c, dir); });
  chmod(dir.c_str(), 0700);
  auto hardlink = dir + "/hardlink";
  check(link(state.c_str(), hardlink.c_str()) == 0, "Cannot prepare hardlink test");
  rejected([&] { wg::load_or_create_identity(c, dir); });
  unlink(hardlink.c_str());
  auto symlink_dir = temporary.path + "/symlink";
  check(symlink(dir.c_str(), symlink_dir.c_str()) == 0, "Cannot prepare symlink test");
  rejected([&] { wg::load_or_create_identity(c, symlink_dir); });
  auto lock_path = dir + "/identity.lock";
  int lock = open(lock_path.c_str(), O_RDWR);
  check(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0, "Cannot prepare concurrent enrollment test");
  rejected([&] { wg::load_or_create_identity(c, dir); });
  close(lock);
  int fd = open(state.c_str(), O_RDWR);
  check(fd >= 0, "Cannot open test identity");
  char original_seed_byte = 0;
  check(pread(fd, &original_seed_byte, 1, 76) == 1, "Cannot read test private seed");
  char corrupt_seed_byte = original_seed_byte ^ 1;
  check(pwrite(fd, &corrupt_seed_byte, 1, 76) == 1, "Cannot corrupt test private seed");
  rejected([&] { wg::load_or_create_identity(c, dir); });
  check(pwrite(fd, &original_seed_byte, 1, 76) == 1, "Cannot restore test private seed");
  check(wg::load_or_create_identity(c, dir).wireguard_public_key_b64 == first.wireguard_public_key_b64,
        "Identity changed after restoring private state");
  char incorrect = 'x';
  check(pwrite(fd, &incorrect, 1, 8) == 1, "Cannot simulate a different boot UUID");
  close(fd);
  rejected([&] { wg::load_or_create_identity(c, dir); });
  rejected([&] { wg::load_or_create_identity(c, temporary.path + "/../identity"); });
  // Corrupt state is rejected, never replaced with a new silent identity.
  auto contents = wg::read_private_file(state);
  rejected([&] { wg::load_or_create_identity(c, dir); });
  check(wg::read_private_file(state) == contents, "Corrupt state was overwritten");
  auto output = temporary.path + "/offer.json";
  wg::write_public_file(output, wg::enrollment_json(c, first));
  rejected([&] { wg::write_public_file(output, "overwrite"); });
  check(wg::read_public_file(output).find(first.boot_id) != std::string::npos, "Public export was overwritten");
}

}  // namespace

int main() {
  try {
    configuration_tests();
    membership_tests();
    large_group_test();
    identity_tests();
    std::cout << "WireGuard configuration/enrollment: " << assertions << " assertions passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "WireGuard test failure: " << error.what() << '\n';
    return 1;
  }
}
