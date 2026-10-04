#include "WireGuardEnrollment.h"
#include "WireGuardAdmission.h"

#include <csignal>
#include <ctime>
#include <iostream>
#include <map>
#include <set>

#include <openssl/crypto.h>

namespace wg = cocoon::wireguard;

namespace {

volatile std::sig_atomic_t cancelled = 0;
void stop_admission(int) { cancelled = 1; }

void usage() {
  std::cout << "Usage:\n"
               "  cocoon-wireguard check-config --config FILE\n"
               "  cocoon-wireguard enroll --config FILE [--state-dir /run/cocoon-wireguard] [--output FILE]\n"
               "  cocoon-wireguard sign-membership --payload FILE --signing-key PEM [--output FILE]\n"
               "  cocoon-wireguard verify-membership --config FILE --membership FILE "
               "[--state-dir /run/cocoon-wireguard]\n"
               "  cocoon-wireguard admit-peer --config FILE --membership FILE --peer NODE "
               "[--state-dir /run/cocoon-wireguard] [--output FILE]\n"
               "\nEnrollment exports public material only. admit-peer requires real TDX/DCAP; network setup follows later.\n";
}

struct SigningSecret {
  std::string pem;
  ~SigningSecret() {
    OPENSSL_cleanse(pem.data(), pem.size());
  }
};

}  // namespace

int main(int argc, char **argv) {
  try {
    std::signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && std::string_view(argv[1]) == "--internal-quote") return wg::evidence_worker_main("quote");
    if (argc == 2 && std::string_view(argv[1]) == "--internal-verify") return wg::evidence_worker_main("verify");
    if (argc == 2 && std::string(argv[1]) == "--help") {
      usage();
      return 0;
    }
    if (argc < 2) {
      usage();
      return 1;
    }
    std::string command = argv[1];
    std::set<std::string> required, optional;
    if (command == "check-config") {
      required = {"--config"};
    } else if (command == "enroll") {
      required = {"--config"};
      optional = {"--state-dir", "--output"};
    } else if (command == "sign-membership") {
      required = {"--payload", "--signing-key"};
      optional = {"--output"};
    } else if (command == "verify-membership") {
      required = {"--config", "--membership"};
      optional = {"--state-dir"};
    } else if (command == "admit-peer") {
      required = {"--config", "--membership", "--peer"};
      optional = {"--state-dir", "--output"};
    } else {
      throw wg::Error("Unknown command; use --help");
    }
    std::map<std::string, std::string> options;
    for (int i = 2; i < argc; i += 2) {
      std::string key = argv[i];
      if (i + 1 >= argc || (!required.contains(key) && !optional.contains(key)) ||
          !options.emplace(key, argv[i + 1]).second) {
        throw wg::Error("Unknown, duplicate, or incomplete command option");
      }
    }
    for (const auto &key : required) {
      if (!options.contains(key) || options.at(key).empty()) {
        throw wg::Error("Missing required option: " + key);
      }
    }
    std::string output;
    if (command == "admit-peer" && !wg::admission_supported()) {
      throw wg::Error("This build has no real TDX/DCAP support; peer admission is disabled");
    }
    if (command == "sign-membership") {
      auto membership = wg::parse_membership_payload(wg::read_public_file(options.at("--payload")));
      SigningSecret secret{wg::read_private_file(options.at("--signing-key"))};
      output = wg::sign_membership(membership, secret.pem);
    } else {
      auto config = wg::parse_config(wg::read_public_file(options.at("--config")));
      if (command == "check-config") {
        output = "Configuration valid\n";
      } else {
        auto state_dir = options.contains("--state-dir") ? options.at("--state-dir") : "/run/cocoon-wireguard";
        auto identity = wg::load_or_create_identity(config, state_dir);
        if (command == "enroll") {
          output = wg::enrollment_json(config, identity);
        } else if (command == "admit-peer") {
          std::signal(SIGINT, stop_admission);
          std::signal(SIGTERM, stop_admission);
          output = wg::admit_peer(config, identity, wg::read_public_file(options.at("--membership")),
                                  options.at("--peer"), [] { return cancelled != 0; });
        } else {
          auto now = std::time(nullptr);
          if (now < 0) {
            throw wg::Error("Cannot read current time");
          }
          auto membership = wg::verify_membership(config, identity,
                                                   wg::read_public_file(options.at("--membership")), now);
          output = wg::membership_payload_json(membership);
        }
      }
    }
    if (options.contains("--output")) {
      wg::write_public_file(options.at("--output"), output);
    } else {
      std::cout << output;
      if (!std::cout) {
        throw wg::Error("Cannot write output");
      }
    }
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "cocoon-wireguard: " << error.what() << '\n';
    return 1;
  }
}
