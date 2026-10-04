#include "WireGuardDevice.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sstream>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

namespace cocoon::wireguard {
namespace {
using Json = nlohmann::json;
constexpr std::size_t max_output = 1024 * 1024;
void require(bool ok, const char *message) { if (!ok) throw Error(message); }
struct Fd {
  int value;
  explicit Fd(int fd) : value(fd) { require(fd >= 0, "Cannot open network helper descriptor"); }
  Fd(const Fd &) = delete;
  ~Fd() { close(value); }
};
struct Child {
  pid_t pid;
  ~Child() { if (pid > 0) { kill(pid, SIGKILL); while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {} } }
};
struct HelperOutput {
  std::string bytes;
  bool sensitive;
  ~HelperOutput() { if (sensitive) OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

const char *executable(NetworkTool tool) {
  switch (tool) {
    case NetworkTool::Ip: return "/usr/sbin/ip";
    case NetworkTool::WireGuard: return "/usr/bin/wg";
    case NetworkTool::Nftables: return "/usr/sbin/nft";
  }
  throw Error("Unknown network helper");
}

class RealNetworkCommands final : public NetworkCommands {
 public:
  std::string run(NetworkTool tool, const std::vector<std::string> &arguments, std::string_view input,
                  int key_fd, const Deadline &deadline) override {
    deadline.check();
    require(input.size() <= max_output && arguments.size() <= 64, "Network helper input exceeds limit");
    require(key_fd < 0 || (tool == NetworkTool::WireGuard &&
                std::find(arguments.begin(), arguments.end(), "/proc/self/fd/3") != arguments.end()),
            "Runtime key may be passed only to WireGuard");
    std::vector<char *> argv{const_cast<char *>(executable(tool))};
    for (const auto &argument : arguments) {
      require(argument.size() <= 1024 && argument.find('\0') == std::string::npos, "Invalid helper argument");
      argv.push_back(const_cast<char *>(argument.c_str()));
    }
    argv.push_back(nullptr);
    std::unique_ptr<Fd> protected_key;
    if (key_fd >= 0) protected_key = std::make_unique<Fd>(fcntl(key_fd, F_DUPFD_CLOEXEC, 10));
    // Give nft its typed public rules over stdin. wg's separate sealed descriptor contains the key.
    Fd in(static_cast<int>(syscall(SYS_memfd_create, "cocoon-wg-command", MFD_CLOEXEC)));
    std::size_t offset = 0;
    while (offset < input.size()) {
      auto n = write(in.value, input.data() + offset, input.size() - offset);
      if (n < 0 && errno == EINTR) continue;
      require(n > 0, "Cannot prepare network helper input");
      offset += static_cast<std::size_t>(n);
    }
    require(lseek(in.value, 0, SEEK_SET) == 0, "Cannot rewind network helper input");
    int pipe_fds[2];
    require(pipe2(pipe_fds, O_CLOEXEC) == 0, "Cannot create network helper pipe");
    Fd out(pipe_fds[0]), writer(pipe_fds[1]);
    auto parent = getpid();
    Child child{fork()};
    require(child.pid >= 0, "Cannot start network helper");
    if (child.pid == 0) {
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent ||
          dup2(in.value, STDIN_FILENO) < 0 || dup2(writer.value, STDOUT_FILENO) < 0 ||
          dup2(writer.value, STDERR_FILENO) < 0) _exit(126);
      if (protected_key && dup2(protected_key->value, 3) < 0) _exit(126);
      if (key_fd < 0) close(3);
      // No certificate, identity lock, admission socket, or unrelated descriptor reaches the tool.
      if (syscall(SYS_close_range, 4U, ~0U, 0U) != 0) _exit(126);
      char env_path[] = "PATH=/usr/sbin:/usr/bin";
      char env_locale[] = "LC_ALL=C";
      char env_keys[] = "WG_HIDE_KEYS=always";
      char *env[] = {env_path, env_locale, env_keys, nullptr};
      execve(executable(tool), argv.data(), env);
      _exit(127);
    }
    // Closing the parent's writer permits EOF. Fd deliberately owns only the read side from here.
    close(writer.value); writer.value = -1;
    require(fcntl(out.value, F_SETFL, O_NONBLOCK) == 0, "Cannot poll network helper output");
    HelperOutput output{{}, key_fd >= 0};
    bool eof = false;
    int status = 0;
    bool exited = false;
    while (!eof || !exited) {
      deadline.check();
      std::array<char, 4096> buffer{};
      auto n = read(out.value, buffer.data(), buffer.size());
      if (n > 0) {
        require(output.bytes.size() + static_cast<std::size_t>(n) <= max_output, "Network helper output exceeds limit");
        output.bytes.append(buffer.data(), static_cast<std::size_t>(n));
        if (output.sensitive) OPENSSL_cleanse(buffer.data(), buffer.size());
      } else if (n == 0) eof = true;
      else require(errno == EAGAIN || errno == EINTR, "Cannot read network helper output");
      if (!exited) {
        auto result = waitpid(child.pid, &status, WNOHANG);
        require(result >= 0 || errno == EINTR, "Cannot reap network helper");
        if (result == child.pid) { exited = true; child.pid = -1; }
      }
      if ((n <= 0 || eof) && (!eof || !exited)) deadline.wait(eof ? -1 : out.value, POLLIN);
    }
    // Helper diagnostics can echo key input; never put them in exceptions or status.
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      throw Error(std::string("Guest network helper failed: ") + executable(tool));
    }
    return output.sensitive ? std::string() : std::move(output.bytes);
  }
};

Json array_json(const std::string &input) {
  auto value = Json::parse(input, nullptr, false);
  require(value.is_array(), "Invalid guest network inventory");
  return value;
}
std::pair<std::uint32_t, unsigned> prefix(std::string value) {
  auto slash = value.find('/');
  unsigned bits = 32;
  if (slash != std::string::npos) {
    auto text = value.substr(slash + 1);
    require(!text.empty() && text.size() <= 2 && std::all_of(text.begin(), text.end(),
        [](char c) { return c >= '0' && c <= '9'; }), "Invalid guest route prefix");
    bits = static_cast<unsigned>(std::stoul(text));
    value.resize(slash);
  }
  in_addr address{};
  require(bits <= 32 && inet_pton(AF_INET, value.c_str(), &address) == 1, "Invalid guest IPv4 route");
  return {ntohl(address.s_addr), bits};
}
bool overlaps(std::string first, std::string second) {
  auto [a, a_bits] = prefix(std::move(first));
  auto [b, b_bits] = prefix(std::move(second));
  auto bits = std::min(a_bits, b_bits);
  auto mask = bits == 0 ? 0U : (~0U << (32 - bits));
  return (a & mask) == (b & mask);
}

Json match(Json left, Json right) {
  bool lookup = right.is_string() && right.get_ref<const std::string &>().starts_with('@');
  return {{"match", {{"op", lookup ? "in" : "=="}, {"left", left}, {"right", right}}}};
}
Json payload(const char *protocol, const char *field) { return {{"payload", {{"protocol", protocol}, {"field", field}}}}; }
Json meta(const char *key) { return {{"meta", {{"key", key}}}}; }

// A static closed gate, independently retained after the interface disappears. No conntrack accept rule.
Json guard_objects(const Config &config, bool legacy = false) {
  std::string table = "cwg_" + config.interface;
  Json objects = Json::array({{{"table", {{"family", "inet"}, {"name", table}}}}});
  if (!legacy) {
    for (const char *name : {"active_peers", "ready_node"}) objects.push_back({{"set", {
        {"family", "inet"}, {"table", table}, {"name", name}, {"type", "ipv4_addr"},
        {"flags", Json::array({"timeout"})}}}});
  }
  auto add_rule = [&](const std::string &chain, Json expressions) {
    objects.push_back({{"rule", {{"family", "inet"}, {"table", table}, {"chain", chain}, {"expr", expressions}}}});
  };
  auto slash = config.overlay_network.find('/');
  Json network = {{"prefix", {{"addr", config.overlay_network.substr(0, slash)},
                               {"len", std::stoi(config.overlay_network.substr(slash + 1))}}}};
  for (std::string chain : {"input", "output", "forward"}) {
    objects.push_back({{"chain", {{"family", "inet"}, {"table", table}, {"name", chain}, {"type", "filter"},
                                   {"hook", chain}, {"prio", -10}, {"policy", "accept"}}}});
    if (chain != "forward") {
      for (const auto &peer : config.peers) {
        bool input = chain == "input";
        for (auto port : {overlay_probe_port, overlay_heartbeat_port}) {
          if (legacy && port == overlay_heartbeat_port) continue;
          add_rule(chain, Json::array({match(meta(input ? "iifname" : "oifname"), config.interface),
            match(payload("ip", "saddr"), input ? peer.overlay_ipv4 : config.overlay_ipv4),
            match(payload("ip", "daddr"), input ? config.overlay_ipv4 : peer.overlay_ipv4),
            match(meta("l4proto"), "udp"), match(payload("udp", "sport"), port),
            match(payload("udp", "dport"), port), {{"accept", nullptr}}}));
        }
        if (!legacy) add_rule(chain, Json::array({match(meta(input ? "iifname" : "oifname"), config.interface),
            match(payload("ip", "saddr"), input ? peer.overlay_ipv4 : config.overlay_ipv4),
            match(payload("ip", "daddr"), input ? config.overlay_ipv4 : peer.overlay_ipv4),
            match(payload("ip", input ? "saddr" : "daddr"), "@active_peers"),
            match(payload("ip", input ? "daddr" : "saddr"), "@ready_node"), {{"accept", nullptr}}}));
      }
    }
    for (const char *field : {"saddr", "daddr"}) {
      add_rule(chain, Json::array({match(payload("ip", field), network), {{"drop", nullptr}}}));
    }
  }
  return objects;
}
Json normalize_guard(Json objects) {
  require(objects.is_array(), "Invalid firewall inventory");
  Json out = Json::array();
  for (auto object : objects) {
    require(object.is_object() && object.size() == 1, "Invalid firewall object");
    if (object.contains("metainfo")) continue;
    auto &body = object.begin().value();
    require(body.is_object(), "Invalid firewall object body");
    body.erase("handle");
    if (object.contains("set")) {
      body.erase("elem");
      if (body.value("policy", "") == "performance") body.erase("policy");
    }
    if (body.contains("flags") && body["flags"] == Json::array()) body.erase("flags");
    // nft's printer may omit redundant protocol dependencies inferred from typed payloads.
    // Remove only those exact dependencies; every address, interface, port and verdict still must match.
    if (object.contains("rule") && body.contains("expr") && body["expr"].is_array()) {
      auto &expressions = body["expr"];
      bool ip = false, udp = false;
      for (const auto &expression : expressions) {
        if (!expression.contains("match")) continue;
        const auto &left = expression["match"].at("left");
        if (left.contains("payload")) {
          ip = ip || left["payload"].value("protocol", "") == "ip";
          udp = udp || left["payload"].value("protocol", "") == "udp";
        }
      }
      for (auto &expression : expressions) if (expression.contains("match")) {
        auto &m = expression["match"];
        if (m.at("right").is_string() && m["right"].get_ref<const std::string &>().starts_with('@') && m["op"] == "==") {
          m["op"] = "in";
        }
      }
      expressions.erase(std::remove_if(expressions.begin(), expressions.end(), [&](const Json &expression) {
        if (!expression.contains("match")) return false;
        const auto &match = expression["match"];
        if (match.value("op", "") != "==" || !match.at("left").contains("meta")) return false;
        auto key = match["left"]["meta"].value("key", "");
        return (udp && key == "l4proto" && (match["right"] == "udp" || match["right"] == 17)) ||
               (ip && key == "nfproto" && (match["right"] == "ipv4" || match["right"] == 2));
      }), expressions.end());
    }
    out.push_back(std::move(object));
  }
  // Kernel enumeration can reorder declarations. Rule order within each chain remains significant.
  Json declarations = Json::array();
  std::map<std::string, Json> rules;
  for (auto &object : out) {
    if (object.contains("rule")) {
      auto chain = object["rule"].at("chain").get<std::string>();
      if (!rules.contains(chain)) rules[chain] = Json::array();
      rules[chain].push_back(std::move(object));
    } else declarations.push_back(std::move(object));
  }
  std::sort(declarations.begin(), declarations.end(), [](const Json &a, const Json &b) { return a.dump() < b.dump(); });
  for (const auto &[chain, items] : rules) for (const auto &item : items) declarations.push_back(item);
  return declarations;
}

Json flush_permissions(const Config &config) {
  Json commands = Json::array();
  for (const char *name : {"active_peers", "ready_node"}) commands.push_back({{"flush", {{"set", {
      {"family", "inet"}, {"table", "cwg_" + config.interface}, {"name", name}}}}}});
  return commands;
}
}  // namespace

std::unique_ptr<NetworkCommands> real_network_commands() { return std::make_unique<RealNetworkCommands>(); }
std::string inspect_guard(const Config &config, NetworkCommands &commands, const Deadline &deadline) {
  auto current = Json::parse(commands.run(NetworkTool::Nftables,
      {"-j", "list", "table", "inet", "cwg_" + config.interface}, {}, -1,
      deadline.within(std::chrono::seconds(5))));
  require(current.is_object() && current.contains("nftables") &&
      normalize_guard(current["nftables"]) == normalize_guard(guard_objects(config)),
      "Installed overlay firewall differs from the owned gate");
  return current.dump(2) + "\n";
}
void install_closed_guard(const Config &config, NetworkCommands &commands, const Deadline &deadline) {
  auto run = [&](std::vector<std::string> args, std::string_view input = {}) {
    return commands.run(NetworkTool::Nftables, args, input, -1, deadline.within(std::chrono::seconds(5)));
  };
  auto tables = Json::parse(run({"-j", "list", "tables"}));
  require(tables.is_object() && tables.contains("nftables"), "Cannot inspect firewall tables");
  bool exists = false;
  for (const auto &object : tables.at("nftables")) {
    if (object.contains("table") && object["table"].value("family", "") == "inet" &&
        object["table"].value("name", "") == "cwg_" + config.interface) exists = true;
  }
  auto expected = guard_objects(config);
  Json transaction = Json::array();
  bool create = !exists;
  if (exists) {
    auto current = Json::parse(run({"-j", "list", "table", "inet", "cwg_" + config.interface}));
    require(current.is_object() && current.contains("nftables"), "Cannot inspect overlay firewall");
    if (normalize_guard(current["nftables"]) == normalize_guard(expected)) {
      transaction = flush_permissions(config);
    } else {
      require(normalize_guard(current["nftables"]) == normalize_guard(guard_objects(config, true)),
              "Existing overlay firewall differs from the owned gate");
      // Upgrade only the exact closed step-3 gate, atomically; unrelated tables are never adopted.
      transaction.push_back({{"delete", {{"table", {{"family", "inet"}, {"name", "cwg_" + config.interface}}}}}});
      create = true;
    }
  }
  if (create) for (const auto &object : expected) {
    transaction.push_back({{object.contains("table") ? "create" : "add", object}});
  }
  run({"-j", "-f", "-"}, Json{{"nftables", transaction}}.dump());
  auto installed = Json::parse(run({"-j", "list", "table", "inet", "cwg_" + config.interface}));
  require(installed.is_object() && installed.contains("nftables") &&
      normalize_guard(installed["nftables"]) == normalize_guard(expected), "Installed overlay firewall differs from the owned gate");
}
WireGuardDevice::WireGuardDevice(const Config &config, NetworkCommands &commands) : config_(config), commands_(commands) {}
WireGuardDevice::~WireGuardDevice() {
  try { stop(Deadline(Deadline::Clock::now() + std::chrono::seconds(5))); } catch (...) {}
}
std::string WireGuardDevice::command(NetworkTool tool, std::vector<std::string> arguments,
    const Deadline &deadline, std::string_view input, int key_fd) {
  return commands_.run(tool, arguments, input, key_fd, deadline.within(std::chrono::seconds(5)));
}

void WireGuardDevice::start(const RuntimeIdentity &identity, const Deadline &deadline) {
  require(!owns_interface_, "WireGuard device is already started");
  require(config_.listen_port != overlay_probe_port && config_.listen_port != overlay_heartbeat_port,
          "WireGuard listen port conflicts with reserved overlay control ports");
  for (const auto &link : array_json(command(NetworkTool::Ip, {"-j", "link", "show"}, deadline))) {
    require(link.at("ifname") != config_.interface, "Refusing to adopt an existing interface");
  }
  for (const auto &link : array_json(command(NetworkTool::Ip, {"-j", "-4", "address", "show"}, deadline))) {
    for (const auto &address : link.at("addr_info")) {
      require(!overlaps(address.at("local").get<std::string>() + "/" +
                           std::to_string(address.at("prefixlen").get<unsigned>()), config_.overlay_network),
              "Overlay overlaps an existing guest address network");
    }
  }
  for (const auto &route : array_json(command(NetworkTool::Ip, {"-j", "-4", "route", "show", "table", "all"}, deadline))) {
    if (route.contains("dst") && route.at("dst") != "default" && route.at("dst") != "0.0.0.0/0") {
      require(!overlaps(route.at("dst"), config_.overlay_network), "Overlay overlaps an existing guest route");
    }
  }
  // Verify outer UDP endpoints have a usable guest route before adding any overlay state.
  for (const auto &peer : config_.peers) {
    auto routes = array_json(command(NetworkTool::Ip, {"-j", "-4", "route", "get", peer.endpoint_ipv4}, deadline));
    require(routes.size() == 1 && routes[0].contains("dev") && routes[0]["dev"] != config_.interface &&
                routes[0].value("type", "unicast") == "unicast", "WireGuard endpoint has no usable underlay route");
  }
  install_closed_guard(config_, commands_, deadline);
  guard_installed_ = true;
  // From here every partial failure leaves the independently closed gate in place.
  ownership_alias_ = "cocoon-wireguard:" + identity.identity().boot_id;
  try {
    // Alias is part of the atomic create request. A timed-out helper may already have created the link.
    owns_interface_ = true;
    command(NetworkTool::Ip, {"link", "add", "dev", config_.interface, "alias", ownership_alias_, "type", "wireguard"}, deadline);
    command(NetworkTool::WireGuard, {"set", config_.interface, "listen-port", std::to_string(config_.listen_port),
        "private-key", "/proc/self/fd/3"}, deadline, {}, identity.key_fd());
    auto public_key = command(NetworkTool::WireGuard, {"show", config_.interface, "public-key"}, deadline);
    require(public_key == identity.identity().wireguard_public_key_b64 + "\n", "WireGuard installed a different local key");
    command(NetworkTool::Ip, {"address", "add", config_.overlay_ipv4 + "/32", "dev", config_.interface}, deadline);
    command(NetworkTool::Ip, {"link", "set", "dev", config_.interface, "mtu", std::to_string(config_.mtu), "up"}, deadline);
  } catch (...) {
    stop(Deadline(Deadline::Clock::now() + std::chrono::seconds(5)));
    throw;
  }
}

void WireGuardDevice::install_peer(const AdmittedSession &session, const Deadline &deadline) {
  require(owns_interface_, "WireGuard device is not started");
  const auto &member = session.peer();
  auto peer = std::find_if(config_.peers.begin(), config_.peers.end(),
      [&](const Peer &p) { return p.node_id == member.node_id && p.overlay_ipv4 == member.overlay_ipv4 &&
                                p.node_rank == member.node_rank; });
  require(peer != config_.peers.end(), "Admitted peer does not match device configuration");
  if (installed_keys_.contains(peer->node_id)) {
    require(installed_keys_.at(peer->node_id) == member.wireguard_public_key_b64, "Renewal changed an installed peer key");
    return;
  }
  try {
    command(NetworkTool::WireGuard, {"set", config_.interface, "peer", member.wireguard_public_key_b64,
        "endpoint", peer->endpoint_ipv4 + ":" + std::to_string(peer->endpoint_port),
        "allowed-ips", peer->overlay_ipv4 + "/32", "persistent-keepalive", std::to_string(config_.keepalive_seconds)}, deadline);
    command(NetworkTool::Ip, {"-4", "route", "add", peer->overlay_ipv4 + "/32", "dev", config_.interface,
        "src", config_.overlay_ipv4}, deadline);
    installed_peers_.push_back(peer->node_id);
    installed_keys_[peer->node_id] = member.wireguard_public_key_b64;
  } catch (...) {
    stop(Deadline(Deadline::Clock::now() + std::chrono::seconds(5)));
    throw;
  }
}
void WireGuardDevice::stop(const Deadline &deadline) {
  if (!owns_interface_) return;
  std::exception_ptr gate_error;
  try { close_workload(deadline); } catch (...) { gate_error = std::current_exception(); }
  auto links = array_json(command(NetworkTool::Ip, {"-j", "link", "show"}, deadline));
  auto link = std::find_if(links.begin(), links.end(), [&](const Json &item) { return item.at("ifname") == config_.interface; });
  if (link == links.end()) { owns_interface_ = false; installed_peers_.clear(); installed_keys_.clear(); return; }
  require(link->value("ifalias", "") == ownership_alias_, "Refusing to delete an interface with different ownership");
  command(NetworkTool::Ip, {"link", "delete", "dev", config_.interface}, deadline);
  owns_interface_ = false;
  installed_peers_.clear();
  installed_keys_.clear();
  if (gate_error) std::rethrow_exception(gate_error);
}

void WireGuardDevice::close_workload(const Deadline &deadline) {
  if (!guard_installed_) return;
  command(NetworkTool::Nftables, {"-j", "-f", "-"}, deadline,
      Json{{"nftables", flush_permissions(config_)}}.dump());
}
bool WireGuardDevice::update_workload(const std::vector<WorkloadPermit> &peers,
                                    Deadline::Clock::time_point group_until, const Deadline &deadline) {
  require(owns_interface_ && guard_installed_, "Cannot activate an unowned WireGuard device");
  auto now = Deadline::Clock::now();
  // Integer JSON timeouts are seconds. Subtract the helper budget and polling margin, then round down.
  auto seconds_left = [&](Deadline::Clock::time_point until) {
    return std::chrono::duration_cast<std::chrono::seconds>(until - now - std::chrono::seconds(2)).count();
  };
  auto group_seconds = seconds_left(group_until);
  Json transaction = flush_permissions(config_);
  auto add = [&](const char *name, const std::string &ip, std::int64_t seconds) {
    transaction.push_back({{"add", {{"element", {{"family", "inet"}, {"table", "cwg_" + config_.interface},
        {"name", name}, {"elem", Json::array({{{"elem", {{"val", ip}, {"timeout", seconds}}}}})}}}}}});
  };
  if (group_seconds > 0) {
    for (const auto &permit : peers) {
      auto peer = std::find_if(config_.peers.begin(), config_.peers.end(), [&](const Peer &p) { return p.node_id == permit.node_id; });
      require(peer != config_.peers.end() && installed_keys_.contains(peer->node_id), "Workload permit has no admitted peer");
      auto seconds = seconds_left(std::min(permit.until, group_until));
      if (seconds > 0) add("active_peers", peer->overlay_ipv4, seconds);
    }
    add("ready_node", config_.overlay_ipv4, group_seconds);
  }
  command(NetworkTool::Nftables, {"-j", "-f", "-"}, deadline.within(std::chrono::seconds(1)),
      Json{{"nftables", transaction}}.dump());
  return group_seconds > 0;
}

void WireGuardDevice::remove_peer(std::string_view node_id, const Deadline &deadline) {
  if (!installed_keys_.contains(std::string(node_id))) return;
  const auto &key = installed_keys_.at(std::string(node_id));
  const auto &peer = *std::find_if(config_.peers.begin(), config_.peers.end(), [&](const Peer &p) { return p.node_id == node_id; });
  command(NetworkTool::WireGuard, {"set", config_.interface, "peer", key, "remove"}, deadline);
  command(NetworkTool::Ip, {"-4", "route", "delete", peer.overlay_ipv4 + "/32", "dev", config_.interface}, deadline);
  installed_keys_.erase(std::string(node_id));
  std::erase(installed_peers_, std::string(node_id));
}
void WireGuardDevice::check_inventory(const Deadline &deadline) {
  require(owns_interface_, "WireGuard device is absent");
  auto links = array_json(command(NetworkTool::Ip, {"-j", "link", "show"}, deadline));
  auto link = std::find_if(links.begin(), links.end(), [&](const Json &item) { return item.at("ifname") == config_.interface; });
  require(link != links.end() && link->value("ifalias", "") == ownership_alias_ &&
      link->value("mtu", 0) == config_.mtu && link->contains("flags") &&
      std::find((*link)["flags"].begin(), (*link)["flags"].end(), "UP") != (*link)["flags"].end(),
      "WireGuard interface was removed, changed, or disabled");
  std::map<std::string, std::string> actual;
  std::istringstream input(command(NetworkTool::WireGuard, {"show", config_.interface, "allowed-ips"}, deadline));
  std::string key, ips;
  while (input >> key >> ips) require(actual.emplace(key, ips).second, "Duplicate kernel WireGuard peer");
  require(input.eof(), "Invalid kernel WireGuard peer inventory");
  std::map<std::string, std::string> expected;
  for (const auto &peer : config_.peers) if (installed_keys_.contains(peer.node_id)) {
    expected[installed_keys_.at(peer.node_id)] = peer.overlay_ipv4 + "/32";
  }
  require(actual == expected, "Kernel WireGuard peers or AllowedIPs changed");
  auto firewall = Json::parse(command(NetworkTool::Nftables, {"-j", "list", "table", "inet", "cwg_" + config_.interface}, deadline));
  require(firewall.contains("nftables") && normalize_guard(firewall["nftables"]) == normalize_guard(guard_objects(config_)),
          "Overlay firewall changed");
}

void cleanup_overlay(const Config &config, const std::string &state_dir, NetworkCommands &commands,
                     const Deadline &deadline) {
  struct stat state{};
  std::unique_ptr<RuntimeIdentity> identity;
  if (lstat((state_dir + "/identity.bin").c_str(), &state) == 0) {
    identity = std::make_unique<RuntimeIdentity>(config, state_dir, false);
  } else require(errno == ENOENT, "Cannot inspect enrolled cleanup identity");
  // The lock, if present, is acquired before withdrawing another process's readiness.
  install_closed_guard(config, commands, deadline);
  auto links = array_json(commands.run(NetworkTool::Ip, {"-j", "link", "show"}, {}, -1, deadline));
  for (const auto &link : links) if (link.at("ifname") == config.interface) {
    require(identity && link.value("ifalias", "") == "cocoon-wireguard:" + identity->identity().boot_id,
            "Cleanup refuses an interface without the enrolled ownership marker");
    commands.run(NetworkTool::Ip, {"link", "delete", "dev", config.interface}, {}, -1, deadline);
  }
  write_runtime_status(state_dir, Json{{"format", "cocoon-wireguard-status-v1"}, {"state", "stopped"},
      {"attestation_type", config.fake_tee ? "fake_tee" : "tdx"},
      {"workload_ready", false}, {"interface", config.interface}}.dump(2) + "\n");
}

void setup_overlay(const Config &config, const std::string &state_dir, std::string_view signed_membership,
                   std::function<bool()> cancelled, std::function<void(std::string_view)> report) {
  require(admission_supported(config), "This build has no real TDX/DCAP support; overlay setup is disabled");
  RuntimeIdentity identity(config, state_dir);
  auto now = std::time(nullptr);
  require(now >= 0, "Cannot read current time");
  auto membership = verify_membership(config, identity.identity(), signed_membership, static_cast<std::uint64_t>(now));
  auto lease_end = Deadline::Clock::now() + std::chrono::seconds(membership.expires_at - static_cast<std::uint64_t>(now));
  Deadline startup(std::min(lease_end, Deadline::Clock::now() + std::chrono::seconds(config.timeouts.startup_seconds)), cancelled);
  auto commands = real_network_commands();
  WireGuardDevice device(config, *commands);
  device.start(identity, startup);
  Json peers = Json::array();
  // A common edge ordering prevents deadlock when more than two ranks perform pairwise admission.
  auto count = config.peers.size() + 1;
  for (std::size_t low = 0; low < count; ++low) {
    for (std::size_t high = low + 1; high < count; ++high) {
      if (config.node_rank != low && config.node_rank != high) continue;
      auto rank = config.node_rank == low ? high : low;
      auto peer = std::find_if(config.peers.begin(), config.peers.end(), [&](const Peer &p) { return p.node_rank == rank; });
      require(peer != config.peers.end(), "Mesh rank is missing");
      startup.check();
      auto admission = admit_peer(config, identity.identity(), signed_membership, peer->node_id,
          [&] { return (cancelled && cancelled()) || Deadline::Clock::now() >= startup.end(); },
          [&](const AdmittedSession &session) {
            device.install_peer(session, startup);
            session.synchronize("device-installed");
            probe_overlay(config, session, startup.within(std::chrono::seconds(config.timeouts.peer_seconds)));
          });
      peers.push_back(Json::parse(admission));
    }
  }
  startup.check();
  verify_membership(config, identity.identity(), signed_membership, static_cast<std::uint64_t>(std::time(nullptr)));
  report(Json{{"format", "cocoon-wireguard-setup-v1"}, {"status", "overlay_probed"}, {"workload_ready", false},
      {"attestation_type", config.fake_tee ? "fake_tee" : "tdx"},
      {"interface", config.interface}, {"overlay_ipv4", config.overlay_ipv4}, {"generation", membership.generation},
      {"expires_at", membership.expires_at}, {"peers", peers}}.dump(2) + "\n");
  Deadline lifetime(lease_end, cancelled);
  try {
    for (;;) {
      auto wall = std::time(nullptr);
      require(wall >= 0 && static_cast<std::uint64_t>(wall) < membership.expires_at, "Membership lease expired");
      lifetime.wait(-1, 0);
    }
  } catch (...) {
    device.stop(Deadline(Deadline::Clock::now() + std::chrono::seconds(5)));
    if (cancelled && cancelled()) return;
    throw;
  }
}
}  // namespace cocoon::wireguard
