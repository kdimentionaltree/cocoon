#pragma once
#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "tee/cocoon/RATLS.h"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace cocoon {

/**
 * @brief Configuration for a single policy
 */
struct PolicyConfig {
  std::string name;
  std::string type;  // "any", "fake_tee", "tee"
  std::string description;
  RATLSPolicyConfig ratls_policy;
};

/**
 * @brief Configuration for a single port
 */
struct PortConfig {
  int port;
  std::string type;  // "socks5", "forward", or "reverse"
  std::string policy_name;
  std::optional<bool> serialize_info;  // If not set, uses global default

  // For forward/reverse proxy
  std::string destination_host;
  int destination_port = 0;

  // For SOCKS5
  bool allow_policy_from_username = false;  // If true, SOCKS5 username can override policy

  // Proof of work (always enabled)
  td::uint8 pow_difficulty = 20;      // Number of leading zero bits required (for reverse proxy)
  td::int32 max_pow_difficulty = 28;  // Max PoW difficulty client will solve (for forward/socks5 proxy)
};
td::StringBuilder &operator<<(td::StringBuilder &sb, const PortConfig &config);

/**
 * @brief Tunnel configuration
 */
struct TunnelConfig {
  enum class TunnelMode { Client, Server };

  std::string name;
  TunnelMode tunnel_mode{TunnelMode::Client};
  std::string interface;
  std::string local_ipv4;
  std::string peer_ipv4;
  int mtu{1400};

  std::string destination_host;
  int destination_port{0};

  std::string listen_host;
  int listen_port{0};
};

/**
 * @brief Main proxy configuration
 */
struct ProxyConfig {
  std::string cert_base_name;
  std::vector<PolicyConfig> policies;
  std::vector<PortConfig> ports;
  std::vector<TunnelConfig> tunnels;
  int threads = 0;
};

/**
 * @brief Parse configuration from JSON value
 * @param json_value Parsed JSON value
 * @return Parsed configuration or error
 */
td::Result<ProxyConfig> parse_config_from_json(td::JsonValue &json_value);

/**
 * @brief Parse configuration from JSON file
 * @param filename Path to JSON configuration file
 * @return Parsed configuration or error
 */
td::Result<ProxyConfig> parse_config_file(const std::string &filename);

/**
 * @brief Generate example configuration as JSON string
 * @return JSON string with example configuration
 */
std::string generate_example_config();

/**
 * @brief Validate port configuration
 * @param config Port configuration to validate
 * @return Status indicating validation result
 */
td::Status validate_port_config(const PortConfig &config);

/**
 * @brief Validate tunnel configuration
 */
td::Status validate_tunnel_config(const TunnelConfig &config);

/**
 * @brief Validate proxy configuration
 * @param config Proxy configuration to validate
 * @return Status indicating validation result
 */
td::Status validate_proxy_config(const ProxyConfig &config);

}  // namespace cocoon
