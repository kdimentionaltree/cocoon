#include "ProxyConfig.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/IPAddress.h"
#include <cctype>
#include <fstream>
#include <set>

#include "tee/cocoon/utils.h"

namespace cocoon {

namespace {

constexpr int MIN_PORT = 1024;
constexpr int MAX_PORT = 65535;
constexpr int MIN_TUNNEL_MTU = 576;
constexpr int MAX_TUNNEL_MTU = 65535;

td::Status validate_port_number(int port) {
  if (port < MIN_PORT || port > MAX_PORT) {
    return td::Status::Error(PSLICE() << "Port must be between " << MIN_PORT << " and " << MAX_PORT << ", got "
                                      << port);
  }
  return td::Status::OK();
}

// Helper functions to parse configuration using TDLib's JSON utilities
td::Result<PolicyConfig> parse_policy_from_json(td::JsonObject &obj) {
  PolicyConfig policy;

  TRY_RESULT(name, obj.get_required_string_field("name"));
  policy.name = std::move(name);

  TRY_RESULT(type, obj.get_required_string_field("type"));
  policy.type = std::move(type);

  auto r_description = obj.get_optional_string_field("description");
  if (r_description.is_ok()) {
    policy.description = r_description.move_as_ok();
  }

  auto r_ratls_policy = obj.extract_optional_field("ratls_policy", td::JsonValue::Type::Object);
  if (r_ratls_policy.is_ok() && r_ratls_policy.ok().type() == td::JsonValue::Type::Object) {
    TRY_RESULT(ratls_policy, parse_ratls_policy_from_json(r_ratls_policy.ok_ref().get_object()));
    policy.ratls_policy = std::move(ratls_policy);
  }

  return policy;
}

td::Result<PortConfig> parse_port_from_json(const td::JsonObject &obj) {
  PortConfig port;

  TRY_RESULT(port_num, obj.get_required_int_field("port"));
  port.port = port_num;

  TRY_RESULT(type, obj.get_required_string_field("type"));
  port.type = std::move(type);

  TRY_RESULT(policy_name, obj.get_required_string_field("policy_name"));
  port.policy_name = std::move(policy_name);

  auto r_dest_host = obj.get_optional_string_field("destination_host");
  if (r_dest_host.is_ok()) {
    port.destination_host = r_dest_host.move_as_ok();
  }

  auto r_dest_port = obj.get_optional_int_field("destination_port");
  if (r_dest_port.is_ok()) {
    port.destination_port = r_dest_port.move_as_ok();
  }

  auto r_allow_policy = obj.get_optional_bool_field("allow_policy_from_username", false);
  if (r_allow_policy.is_ok()) {
    port.allow_policy_from_username = r_allow_policy.move_as_ok();
  }

  // Only set serialize_info if explicitly present in JSON
  //if (obj.has_field("serialize_info")) {
  auto r_serialize_info = obj.get_optional_bool_field("serialize_info", false);
  if (r_serialize_info.is_ok()) {
    port.serialize_info = r_serialize_info.move_as_ok();
    LOG(ERROR) << "SERIALIZE_INFO=" << (port.serialize_info.value() ? "YES" : "NO");
  }
  //}
  // Otherwise leave as nullopt to use global default

  // Parse PoW configuration (always enabled)
  auto r_pow_difficulty = obj.get_optional_int_field("pow_difficulty");
  if (r_pow_difficulty.is_ok()) {
    port.pow_difficulty = static_cast<td::uint8>(r_pow_difficulty.move_as_ok());
  }

  auto r_max_pow_difficulty = obj.get_optional_int_field("max_pow_difficulty");
  if (r_max_pow_difficulty.is_ok()) {
    port.max_pow_difficulty = static_cast<td::int32>(r_max_pow_difficulty.move_as_ok());
  }

  return port;
}

td::Result<TunnelConfig> parse_tunnel_from_json(const td::JsonObject &obj) {
  TunnelConfig tunnel;

  TRY_RESULT(name, obj.get_required_string_field("name"));
  tunnel.name = std::move(name);
  TRY_RESULT(mode, obj.get_required_string_field("mode"));
  if (mode == "client") {
    tunnel.tunnel_mode = TunnelConfig::TunnelMode::Client;
  } else if (mode == "server") {
    tunnel.tunnel_mode = TunnelConfig::TunnelMode::Server;
  } else {
    return td::Status::Error(PSLICE() << "Invalid tunnel mode: " << mode << ". Must be 'client' or 'server'");
  }

  TRY_RESULT(interface, obj.get_required_string_field("interface"));
  tunnel.interface = std::move(interface);
  TRY_RESULT(local_ipv4, obj.get_required_string_field("local_ipv4"));
  tunnel.local_ipv4 = std::move(local_ipv4);
  TRY_RESULT(peer_ipv4, obj.get_required_string_field("peer_ipv4"));
  tunnel.peer_ipv4 = std::move(peer_ipv4);
  TRY_RESULT(mtu, obj.get_optional_int_field("mtu", tunnel.mtu));
  tunnel.mtu = mtu;

  if (tunnel.tunnel_mode == TunnelConfig::TunnelMode::Client) {
    if (obj.has_field("listen_host") || obj.has_field("listen_port")) {
      return td::Status::Error("Client tunnel cannot specify listen_host or listen_port");
    }
    TRY_RESULT(destination_host, obj.get_required_string_field("destination_host"));
    tunnel.destination_host = std::move(destination_host);
    TRY_RESULT(destination_port, obj.get_required_int_field("destination_port"));
    tunnel.destination_port = destination_port;
  } else {
    if (obj.has_field("destination_host") || obj.has_field("destination_port")) {
      return td::Status::Error("Server tunnel cannot specify destination_host or destination_port");
    }
    TRY_RESULT(listen_host, obj.get_optional_string_field("listen_host", "0.0.0.0"));
    tunnel.listen_host = std::move(listen_host);
    TRY_RESULT(listen_port, obj.get_required_int_field("listen_port"));
    tunnel.listen_port = listen_port;
  }

  return tunnel;
}
}  // anonymous namespace

td::StringBuilder &operator<<(td::StringBuilder &sb, const PortConfig &config) {
  sb << config.type << " port=" << config.port;

  if (config.type == "forward" || config.type == "reverse") {
    sb << " -> " << config.destination_host << ":" << config.destination_port;
  }

  sb << " @" << config.policy_name;

  if (config.serialize_info.has_value()) {
    sb << " serialize_info=" << (config.serialize_info.value() ? "true" : "false");
  }

  if (config.allow_policy_from_username) {
    sb << " allow_policy_from_username=true";
  }

  if (config.serialize_info && config.serialize_info.value()) {
    sb << " serialize_info=true";
  }

  return sb;
}

td::Result<ProxyConfig> parse_config_from_json(td::JsonValue &json_value) {
  if (json_value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Configuration must be a JSON object");
  }

  auto &obj = json_value.get_object();
  ProxyConfig config;

  // Parse optional cert_base_name
  auto r_cert = obj.get_optional_string_field("cert_base_name");
  if (r_cert.is_ok()) {
    config.cert_base_name = r_cert.move_as_ok();
  }

  // Parse optional threads
  auto r_threads = obj.get_optional_int_field("threads");
  if (r_threads.is_ok()) {
    config.threads = r_threads.move_as_ok();
  }

  // Parse optional policies array
  if (obj.has_field("policies")) {
    TRY_RESULT(policies_value, obj.extract_optional_field("policies", td::JsonValue::Type::Array));
    auto &policies_array = policies_value.get_array();
    for (auto &policy_value : policies_array) {
      if (policy_value.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("Each policy must be an object");
      }
      TRY_RESULT(policy, parse_policy_from_json(policy_value.get_object()));
      config.policies.push_back(std::move(policy));
    }
  }

  // Proxy ports and tunnels are independently optional service arrays.
  if (obj.has_field("ports")) {
    TRY_RESULT(ports_value, obj.extract_required_field("ports", td::JsonValue::Type::Array));
    for (const auto &port_value : ports_value.get_array()) {
      if (port_value.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("Each port must be an object");
      }
      TRY_RESULT(port, parse_port_from_json(port_value.get_object()));
      config.ports.push_back(std::move(port));
    }
  }

  if (obj.has_field("tunnels")) {
    TRY_RESULT(tunnels_value, obj.extract_required_field("tunnels", td::JsonValue::Type::Array));
    for (const auto &tunnel_value : tunnels_value.get_array()) {
      if (tunnel_value.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("Each tunnel must be an object");
      }
      TRY_RESULT(tunnel, parse_tunnel_from_json(tunnel_value.get_object()));
      config.tunnels.push_back(std::move(tunnel));
    }
  }

  return config;
}

td::Result<cocoon::ProxyConfig> parse_config_file(const std::string &filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    return td::Status::Error(PSLICE() << "Cannot open config file: " << filename
                                      << " (file not found or permission denied)");
  }

  std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  file.close();

  TRY_RESULT(json_value, td::json_decode(content));
  TRY_RESULT(config, cocoon::parse_config_from_json(json_value));
  TRY_STATUS(validate_proxy_config(config));

  return config;
}

std::string generate_example_config() {
  return R"({
  "cert_base_name": "",
  "threads": 0,
  "policies": [
    {
      "name": "any",
      "type": "any",
      "description": "Allow any connection without TEE validation"
    },
    {
      "name": "fake_tee",
      "type": "fake_tee",
      "description": "Use fake TEE for testing"
    },
    {
      "name": "tee",
      "type": "tee",
      "description": "Use real TEE validation"
    },
    {
      "name": "strict_tee",
      "type": "tee",
      "description": "TEE policy with advanced validation settings",
      "ratls_policy": {
        "tdx_config": {
          "allowed_image_hashes": [
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
          ],
          "allowed_collateral_root_hashes": [
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
          ],
          "allowed_mrtd": [
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
          ],
          "allowed_rtmr": [
            [
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
              "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ]
           ]
        },
        "sev_config": {
          "allowed_measurement": [
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
          ],
          "allowed_image_id": [
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
          ]
        }
      }
    }
  ],
  "ports": [
    {
      "port": 8116,
      "type": "socks5",
      "policy_name": "any",
      "allow_policy_from_username": true
    },
    {
      "port": 8117,
      "type": "reverse",
      "policy_name": "tee",
      "destination_host": "localhost",
      "destination_port": 8118,
      "serialize_info": true
    },
    {
      "port": 8118,
      "type": "reverse",
      "policy_name": "fake_tee",
      "destination_host": "localhost",
      "destination_port": 8119
    }
  ],
  "tunnels": [
    {
      "name": "cluster",
      "mode": "client",
      "interface": "tun0",
      "local_ipv4": "10.77.0.1",
      "peer_ipv4": "10.77.0.2",
      "mtu": 1400,
      "destination_host": "B_HOST_IP",
      "destination_port": 12002
    },
    {
      "name": "cluster",
      "mode": "server",
      "interface": "tun0",
      "local_ipv4": "10.77.0.2",
      "peer_ipv4": "10.77.0.1",
      "mtu": 1400,
      "listen_host": "0.0.0.0",
      "listen_port": 12002
    }
  ]
})";
}

td::Status validate_port_config(const PortConfig &config) {
  TRY_STATUS(validate_port_number(config.port));

  if (config.type != "socks5" && config.type != "reverse" && config.type != "forward") {
    return td::Status::Error(PSLICE() << "Invalid port type: " << config.type
                                      << ". Must be 'socks5', 'forward', or 'reverse'");
  }

  if (config.policy_name.empty()) {
    return td::Status::Error("Policy name cannot be empty");
  }

  if (config.type == "reverse" || config.type == "forward") {
    if (config.destination_host.empty()) {
      return td::Status::Error(PSLICE() << config.type << " proxy must have destination host");
    }
    TRY_STATUS(validate_port_number(config.destination_port));
  }

  return td::Status::OK();
}

td::Status validate_tunnel_config(const TunnelConfig &config) {
  if (config.name.empty() || config.name.find('\0') != std::string::npos) {
    return td::Status::Error("Tunnel name must be non-empty and contain no null bytes");
  }
  if (config.mtu < MIN_TUNNEL_MTU || config.mtu > MAX_TUNNEL_MTU) {
    return td::Status::Error(PSLICE() << "Tunnel MTU must be between " << MIN_TUNNEL_MTU << " and " << MAX_TUNNEL_MTU);
  }

  switch (config.tunnel_mode) {
    case TunnelConfig::TunnelMode::Client:
      if (config.destination_host.empty()) {
        return td::Status::Error("Client tunnel must have destination_host");
      }
      for (unsigned char c : config.destination_host) {
        if (c == '\0' || c == '/' || c == ':' || c == '[' || c == ']' || std::isspace(c)) {
          return td::Status::Error("Client tunnel destination_host must be an IPv4 address or hostname");
        }
      }
      TRY_STATUS(validate_port_number(config.destination_port));
      if (!config.listen_host.empty() || config.listen_port != 0) {
        return td::Status::Error("Client tunnel cannot specify a listener");
      }
      break;
    case TunnelConfig::TunnelMode::Server: {
      TRY_STATUS(validate_port_number(config.listen_port));
      if (config.listen_host.find('\0') != std::string::npos) {
        return td::Status::Error("Tunnel listen_host contains a null byte");
      }
      td::IPAddress address;
      TRY_STATUS(address.init_ipv4_port(config.listen_host, config.listen_port));
      auto first_octet = td::to_integer<int>(td::split(config.listen_host, '.').first);
      if (first_octet >= 224 || (first_octet == 0 && config.listen_host != "0.0.0.0")) {
        return td::Status::Error("Tunnel listen_host must be a unicast IPv4 address or 0.0.0.0");
      }
      if (!config.destination_host.empty() || config.destination_port != 0) {
        return td::Status::Error("Server tunnel cannot specify a destination");
      }
      break;
    }
    default:
      return td::Status::Error("Invalid tunnel mode");
  }
  return td::Status::OK();
}

td::Status validate_proxy_config(const ProxyConfig &config) {
  if (config.ports.empty() && config.tunnels.empty()) {
    return td::Status::Error("No ports or tunnels configured");
  }

  if (config.threads < 0) {
    return td::Status::Error("Number of threads must be non-negative");
  }

  // Check for duplicate ports
  std::set<int> used_ports;
  for (const auto &port_config : config.ports) {
    TRY_STATUS(validate_port_config(port_config));

    if (used_ports.count(port_config.port)) {
      return td::Status::Error(PSLICE() << "Duplicate port: " << port_config.port);
    }
    used_ports.insert(port_config.port);
  }

  std::set<std::string> tunnel_names;
  std::set<std::string> tunnel_interfaces;
  std::set<std::string> tunnel_peers;
  std::set<std::string> tunnel_local_addresses;
  for (const auto &tunnel : config.tunnels) {
    TRY_STATUS(validate_tunnel_config(tunnel));
    if (!tunnel_names.insert(tunnel.name).second) {
      return td::Status::Error(PSLICE() << "Duplicate tunnel name: " << tunnel.name);
    }
    if (!tunnel_interfaces.insert(tunnel.interface).second) {
      return td::Status::Error(PSLICE() << "Duplicate tunnel interface: " << tunnel.interface);
    }
    if (!tunnel_peers.insert(tunnel.peer_ipv4).second) {
      return td::Status::Error(PSLICE() << "Duplicate tunnel peer route: " << tunnel.peer_ipv4);
    }
    tunnel_local_addresses.insert(tunnel.local_ipv4);
    if (tunnel.tunnel_mode == TunnelConfig::TunnelMode::Server && !used_ports.insert(tunnel.listen_port).second) {
      return td::Status::Error(PSLICE() << "Duplicate listener port: " << tunnel.listen_port);
    }
  }
  for (const auto &tunnel : config.tunnels) {
    if (tunnel_local_addresses.count(tunnel.peer_ipv4)) {
      return td::Status::Error(PSLICE() << "Tunnel peer route conflicts with local address: " << tunnel.peer_ipv4);
    }
    if (tunnel.tunnel_mode == TunnelConfig::TunnelMode::Client &&
        (tunnel_peers.count(tunnel.destination_host) || tunnel_local_addresses.count(tunnel.destination_host))) {
      return td::Status::Error("Tunnel destination_host conflicts with a tunnel address or peer route");
    }
  }

  // Validate policy references
  std::set<std::string> defined_policies;
  for (const auto &policy : config.policies) {
    if (policy.name.empty()) {
      return td::Status::Error("Policy name cannot be empty");
    }
    if (policy.type.empty()) {
      return td::Status::Error(PSLICE() << "Policy type cannot be empty for policy: " << policy.name);
    }
    if (policy.type != "any" && policy.type != "fake_tee" && policy.type != "tee") {
      return td::Status::Error(PSLICE() << "Invalid policy type: " << policy.type << " for policy: " << policy.name);
    }
    defined_policies.insert(policy.name);
  }

  // Add default policies
  defined_policies.insert("any");
  defined_policies.insert("fake_tee");
  defined_policies.insert("tee");

  for (const auto &port_config : config.ports) {
    if (!defined_policies.count(port_config.policy_name)) {
      return td::Status::Error(PSLICE() << "Unknown policy: " << port_config.policy_name << " referenced by port "
                                        << port_config.port);
    }
  }

  return td::Status::OK();
}

}  // namespace cocoon
