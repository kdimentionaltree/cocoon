#include "WireGuardAdmission.h"

#include "tee/cocoon/tdx/tdx.h"
#include "tee/cocoon/tdx/RATLS.h"
#include "tee/cocoon/sev/ABI.h"
#include "tee/cocoon/sev/RATLS.h"
#include "td/utils/as.h"
#include "td/utils/misc.h"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <openssl/pem.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace cocoon::wireguard {
namespace {

constexpr std::size_t max_quote = 32768;

struct Fd {
  int value;
  explicit Fd(int fd) : value(fd) {}
  Fd(const Fd &) = delete;
  ~Fd() { if (value >= 0) close(value); }
};

// Blocking DCAP/library calls run in an exec'd child, so cancellation never leaves a detached verifier.
struct Child {
  pid_t pid;
  ~Child() {
    if (pid > 0) {
      kill(pid, SIGKILL);
      while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
    }
  }
};

std::string worker(std::string_view operation, std::string_view input, const Deadline &deadline) {
  deadline.check();
  int descriptors[2];
  if (pipe2(descriptors, O_CLOEXEC) != 0) throw Error("Cannot create attestation output pipe");
  Fd read_end(descriptors[0]), write_end(descriptors[1]);
  int request[2];
  if (pipe2(request, O_CLOEXEC) != 0) throw Error("Cannot create attestation input pipe");
  Fd input_read(request[0]), input_write(request[1]);
  // The child drains the bounded request before replying; parent writes are nonblocking and deadline-aware.
  auto expected_parent = getpid();
  auto pid = fork();
  if (pid < 0) throw Error("Cannot start attestation worker");
  if (pid == 0) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent) _exit(1);
    if (dup2(input_read.value, STDIN_FILENO) < 0 || dup2(write_end.value, STDOUT_FILENO) < 0) _exit(1);
    execl("/proc/self/exe", "cocoon-wireguard", operation == "quote" ? "--internal-quote" : "--internal-verify",
          static_cast<char *>(nullptr));
    _exit(1);
  }
  Child child{pid};
  close(input_read.value); input_read.value = -1;
  close(write_end.value); write_end.value = -1;
  if (fcntl(input_write.value, F_SETFL, O_NONBLOCK) < 0 || fcntl(read_end.value, F_SETFL, O_NONBLOCK) < 0) {
    throw Error("Cannot configure attestation pipes");
  }
  while (!input.empty()) {
    deadline.check();
    auto n = write(input_write.value, input.data(), input.size());
    if (n > 0) input.remove_prefix(static_cast<std::size_t>(n));
    else if (n < 0 && (errno == EAGAIN || errno == EINTR)) deadline.wait(input_write.value, POLLOUT);
    else throw Error("Attestation worker rejected its input");
  }
  close(input_write.value); input_write.value = -1;
  std::string output;
  std::array<char, 4096> buffer{};
  for (;;) {
    deadline.check();
    auto n = read(read_end.value, buffer.data(), buffer.size());
    if (n == 0) break;
    if (n > 0) {
      if (output.size() + static_cast<std::size_t>(n) > max_quote) throw Error("Attestation output exceeds limit");
      output.append(buffer.data(), static_cast<std::size_t>(n));
    } else if (errno == EAGAIN || errno == EINTR) deadline.wait(read_end.value, POLLIN);
    else throw Error("Cannot read attestation worker output");
  }
  int status = 0;
  for (;;) {
    deadline.check();
    auto result = waitpid(pid, &status, WNOHANG);
    if (result == pid) break;
    if (result < 0 && errno != EINTR) throw Error("Cannot reap attestation worker");
    deadline.wait(-1, 0);
  }
  child.pid = -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) throw Error("Real TDX attestation failed");
  return output;
}

class RealEvidence final : public EvidenceProvider {
 public:
  std::string quote(std::string_view reportdata, const Deadline &deadline) override {
    if (reportdata.size() != 64) throw Error("Invalid admission REPORTDATA size");
    auto result = run_evidence_worker("quote", reportdata, deadline);
    if (result.empty()) throw Error("Empty TDX quote");
    return result;
  }
  Evidence verify(std::string_view quote, const Deadline &deadline) override {
    if (quote.empty() || quote.size() > max_quote) throw Error("Invalid TDX quote size");
    auto result = run_evidence_worker("verify", quote, deadline);
    if (result.size() != 105) throw Error("Invalid attestation verification response");
    Evidence evidence{result.substr(0, 64), td::hex_encode(td::Slice(result).substr(64, 32)), 0, result[104] != 0};
    for (std::size_t i = 96; i < 104; ++i) {
      evidence.td_attributes = (evidence.td_attributes << 8) | static_cast<unsigned char>(result[i]);
    }
    return evidence;
  }
};

// Matches gen-cert --tee fake_tee on Intel and AMD. These reports are forgeable;
// only a separately signed fake membership and explicit debug configuration may use them.
class FakeEvidence final : public EvidenceProvider {
 public:
  explicit FakeEvidence(const Config &config) {
    auto pem = read_public_file(config.cert_base_name + "_cert.pem");
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr,
                                                  X509_free);
    if (!cert) throw Error("Cannot read fake-TEE certificate");
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(OBJ_txt2obj("1.3.6.1.4.1.12345.101", 1), ASN1_OBJECT_free);
    sev_ = X509_get_ext_by_OBJ(cert.get(), oid.get(), -1) >= 0;
  }
  std::string quote(std::string_view reportdata, const Deadline &deadline) override {
    deadline.check();
    if (reportdata.size() != 64) throw Error("Invalid fake REPORTDATA size");
    if (sev_) {
      sev::AttestationReport report{};
      std::memcpy(report.report_data.raw, reportdata.data(), reportdata.size());
      return {reinterpret_cast<const char *>(&report), sizeof(report)};
    }
    tdx::RATLSAttestationReport report{};
    std::memcpy(report.reportdata.raw, reportdata.data(), reportdata.size());
    return td::serialize(report);
  }
  Evidence verify(std::string_view quote, const Deadline &deadline) override {
    deadline.check();
    if (quote.size() == sizeof(sev::AttestationReport)) {
      sev::AttestationReport report{};
      std::memcpy(&report, quote.data(), sizeof(report));
      sev::AttestationReport expected{};
      expected.report_data = report.report_data;
      if (std::memcmp(&report, &expected, sizeof(report)) != 0) throw Error("Not a synthetic SEV report");
      sev::RATLSAttestationReport fake{};
      fake.reportdata = report.report_data;
      return {report.report_data.as_slice().str(), td::hex_encode(sev::image_hash(fake).as_slice()), 0, false};
    }
    // Exact size and round-trip check reject truncation, trailing bytes and all nonzero measurements.
    tdx::RATLSAttestationReport report{};
    auto parsed = td::unserialize(report, td::Slice(quote.data(), quote.size()));
    if (parsed.is_error()) throw Error("Invalid synthetic TDX report");
    tdx::RATLSAttestationReport expected{};
    expected.reportdata = report.reportdata;
    if (td::serialize(expected) != quote) throw Error("Not a synthetic TDX report");
    return {report.reportdata.as_slice().str(), td::hex_encode(tdx::image_hash(report).as_slice()), 0, false};
  }
 private:
  bool sev_{};
};

}  // namespace

std::string run_evidence_worker(std::string_view operation, std::string_view input, const Deadline &deadline) {
  if ((operation != "quote" && operation != "verify") || input.empty() || input.size() > max_quote) {
    throw Error("Invalid evidence worker operation or input size");
  }
  return worker(operation, input, deadline);
}

bool admission_supported() {
#if TD_TDX_ATTESTATION
  return true;
#else
  return false;
#endif
}

bool admission_supported(const Config &config) {
  return config.fake_tee || admission_supported();
}

std::unique_ptr<EvidenceProvider> evidence_provider(const Config &config) {
  if (config.fake_tee) return std::make_unique<FakeEvidence>(config);
  return real_evidence_provider();
}

std::unique_ptr<EvidenceProvider> real_evidence_provider() {
  if (!admission_supported()) throw Error("This build has no real TDX/DCAP support; peer admission is disabled");
  return std::make_unique<RealEvidence>();
}

int evidence_worker_main(std::string_view operation) {
  try {
    // Internal helpers are not a general-purpose quote oracle. Only this running executable may launch them.
    struct stat self{}, parent{};
    auto parent_executable = "/proc/" + std::to_string(getppid()) + "/exe";
    if (stat("/proc/self/exe", &self) != 0 || stat(parent_executable.c_str(), &parent) != 0 ||
        self.st_dev != parent.st_dev || self.st_ino != parent.st_ino) {
      throw Error("Evidence worker must be launched by the admission process");
    }
    std::string input;
    std::array<char, 4096> buffer{};
    for (;;) {
      auto n = read(STDIN_FILENO, buffer.data(), buffer.size());
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) throw Error("Cannot read evidence request");
      if (n == 0) break;
      if (input.size() + static_cast<std::size_t>(n) > max_quote) throw Error("Evidence request exceeds limit");
      input.append(buffer.data(), static_cast<std::size_t>(n));
    }
    std::string output;
    if (operation == "quote") {
      if (input.size() != 64) throw Error("Invalid REPORTDATA size");
      auto result = tdx::tdx_make_quote(td::as<td::UInt512>(input.data()));
      if (result.is_error()) throw Error("TDX quote generation failed");
      output = result.move_as_ok().raw_quote;
    } else if (operation == "verify") {
      auto result = tdx::tdx_verify_quote({input});
      if (result.is_error()) throw Error("TDX quote verification failed");
      auto verified = result.move_as_ok();
      output = verified.parsed.attestation.reportdata.as_slice().str();
      output += tdx::image_hash(verified.parsed.attestation).as_slice().str();
      for (unsigned i = 8; i > 0; --i) {
        output += static_cast<char>(verified.parsed.td_attributes >> (8 * (i - 1)));
      }
      output += static_cast<char>(verified.parsed.has_service_td);
    } else throw Error("Unknown evidence operation");
    std::cout.write(output.data(), static_cast<std::streamsize>(output.size()));
    return std::cout ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << "Attestation worker: " << error.what() << '\n';
    return 1;
  }
}

}  // namespace cocoon::wireguard
