#include "WireGuardEnrollment.h"
#include "WireGuardRuntimeIdentity.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <functional>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace cocoon::wireguard {
namespace {

constexpr std::size_t max_file_size = 65536;
constexpr std::size_t boot_uuid_size = 36;
constexpr char identity_magic[] = "CWGKEY1";
constexpr std::size_t identity_size = sizeof(identity_magic) + boot_uuid_size + 32 + 32 + 32;
constexpr std::size_t boot_offset = sizeof(identity_magic) + boot_uuid_size;
constexpr std::size_t key_offset = boot_offset + 32;
constexpr std::size_t context_offset = key_offset + 32;

[[noreturn]] void system_error(const char *message) {
  throw Error(std::string(message) + ": " + std::strerror(errno));
}

struct Fd {
  int value{-1};
  explicit Fd(int fd) : value(fd) {
  }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  Fd(Fd &&other) noexcept : value(std::exchange(other.value, -1)) {
  }
  ~Fd() {
    if (value >= 0) {
      close(value);
    }
  }
};

struct Secret {
  std::array<unsigned char, identity_size> bytes{};
  ~Secret() {
    OPENSSL_cleanse(bytes.data(), bytes.size());
  }
};

std::array<unsigned char, 32> state_digest(std::string_view context, const Secret &state) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  std::array<unsigned char, 32> digest{};
  unsigned size = 0;
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx.get(), context.data(), context.size()) != 1 ||
      EVP_DigestUpdate(ctx.get(), state.bytes.data(), context_offset) != 1 ||
      EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) != 1 || size != digest.size()) {
    throw Error("Cannot hash identity context and state");
  }
  return digest;
}

void private_permissions(int fd, bool directory) {
  struct stat s{};
  if (fstat(fd, &s) != 0) {
    system_error("Cannot inspect private state");
  }
  auto mode = directory ? 0700 : 0600;
  if ((directory ? !S_ISDIR(s.st_mode) : !S_ISREG(s.st_mode)) || s.st_uid != geteuid() ||
      (s.st_mode & 07777) != mode || (!directory && s.st_nlink != 1)) {
    throw Error("Private state must be owned by this user with exact 0700 directory / 0600 file permissions "
                "and no hard links");
  }
}

Fd private_directory(const std::string &path) {
  if (path.size() < 2 || path.front() != '/' || path.back() == '/' || path.find('\0') != std::string::npos) {
    throw Error("State directory must be an absolute normalized path");
  }
  Fd dir(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (dir.value < 0) {
    system_error("Cannot open filesystem root");
  }
  for (std::size_t start = 1; start < path.size();) {
    auto end = path.find('/', start);
    if (end == std::string::npos) {
      end = path.size();
    }
    auto component = path.substr(start, end - start);
    if (component.empty() || component == "." || component == "..") {
      throw Error("State directory must be normalized");
    }
    // Create only the final directory. Parent directories must already exist.
    if (end == path.size() && mkdirat(dir.value, component.c_str(), 0700) != 0 && errno != EEXIST) {
      system_error("Cannot create private state directory");
    }
    Fd next(openat(dir.value, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (next.value < 0) {
      system_error("Cannot open state directory without following symlinks");
    }
    std::swap(dir.value, next.value);
    start = end + 1;
  }
  private_permissions(dir.value, true);
  return dir;
}

void write_all(int fd, std::string_view data) {
  while (!data.empty()) {
    auto size = write(fd, data.data(), data.size());
    if (size < 0 && errno == EINTR) {
      continue;
    }
    if (size <= 0) {
      system_error("Cannot write file");
    }
    data.remove_prefix(size);
  }
}

std::string read_all(int fd) {
  std::string out;
  std::array<char, 4096> buffer{};
  for (;;) {
    auto size = read(fd, buffer.data(), buffer.size());
    if (size < 0 && errno == EINTR) {
      continue;
    }
    if (size < 0) {
      system_error("Cannot read file");
    }
    if (size == 0) {
      return out;
    }
    if (out.size() + size > max_file_size) {
      throw Error("File size exceeds limit");
    }
    out.append(buffer.data(), size);
  }
}

Fd open_regular_file(const std::string &path) {
  if (path.find('\0') != std::string::npos) {
    throw Error("Invalid file path");
  }
  Fd fd(open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  if (fd.value < 0) {
    system_error("Cannot open file");
  }
  struct stat s{};
  if (fstat(fd.value, &s) != 0) {
    system_error("Cannot inspect file");
  }
  if (!S_ISREG(s.st_mode) || s.st_size < 0 || static_cast<std::uint64_t>(s.st_size) > max_file_size) {
    throw Error("Input must be a bounded regular file");
  }
  return fd;
}

std::string os_boot_uuid() {
  Fd fd(open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC));
  if (fd.value < 0) {
    system_error("Cannot read kernel boot identity");
  }
  auto uuid = read_all(fd.value);
  if (uuid.size() == boot_uuid_size + 1 && uuid.back() == '\n') {
    uuid.pop_back();
  }
  if (uuid.size() != boot_uuid_size) {
    throw Error("Invalid kernel boot identity");
  }
  for (std::size_t i = 0; i < uuid.size(); ++i) {
    bool hyphen = i == 8 || i == 13 || i == 18 || i == 23;
    if ((hyphen && uuid[i] != '-') || (!hyphen && !((uuid[i] >= '0' && uuid[i] <= '9') ||
                                                  (uuid[i] >= 'a' && uuid[i] <= 'f')))) {
      throw Error("Invalid kernel boot identity");
    }
  }
  return uuid;
}

std::string hex(const unsigned char *data, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < size; ++i) {
    out += digits[data[i] >> 4];
    out += digits[data[i] & 15];
  }
  return out;
}

}  // namespace

std::string read_public_file(const std::string &path) {
  auto fd = open_regular_file(path);
  return read_all(fd.value);
}

std::string read_private_file(const std::string &path) {
  auto fd = open_regular_file(path);
  private_permissions(fd.value, false);
  return read_all(fd.value);
}

void write_public_file(const std::string &path, std::string_view content) {
  if (path.find('\0') != std::string::npos) {
    throw Error("Invalid output path");
  }
  Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644));
  if (fd.value < 0) {
    system_error("Cannot create output (existing files are not overwritten)");
  }
  try {
    write_all(fd.value, content);
    if (fsync(fd.value) != 0) {
      system_error("Cannot persist output");
    }
  } catch (...) {
    unlink(path.c_str());
    throw;
  }
}

namespace {
Identity use_identity(const Config &config, const std::string &state_dir,
    const std::function<void(int, std::string_view)> &use_key = {}, bool create_if_missing = true) {
  auto dir = private_directory(state_dir);
  Fd lock(openat(dir.value, "identity.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600));
  if (lock.value < 0) {
    system_error("Cannot open identity lock");
  }
  private_permissions(lock.value, false);
  if (flock(lock.value, LOCK_EX | LOCK_NB) != 0) {
    system_error("Identity is in use by another process");
  }
  auto uuid = os_boot_uuid();
  auto context = identity_context(config);
  Secret state;
  Fd existing(openat(dir.value, "identity.bin", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  if (existing.value >= 0) {
    private_permissions(existing.value, false);
    struct stat s{};
    if (fstat(existing.value, &s) != 0 || s.st_size != identity_size) {
      throw Error("Invalid saved identity size");
    }
    std::size_t offset = 0;
    while (offset < state.bytes.size()) {
      auto size = read(existing.value, state.bytes.data() + offset, state.bytes.size() - offset);
      if (size < 0 && errno == EINTR) {
        continue;
      }
      if (size <= 0) {
        throw Error("Cannot read saved identity");
      }
      offset += size;
    }
    auto digest = state_digest(context, state);
    if (std::memcmp(state.bytes.data(), identity_magic, sizeof(identity_magic)) != 0 ||
        std::memcmp(state.bytes.data() + sizeof(identity_magic), uuid.data(), uuid.size()) != 0 ||
        CRYPTO_memcmp(state.bytes.data() + context_offset, digest.data(), digest.size()) != 0) {
      throw Error("Saved identity is corrupt or belongs to another boot or enrollment context; "
                  "use a fresh runtime directory");
    }
  } else {
    if (errno != ENOENT) {
      system_error("Cannot open saved identity");
    }
    if (!create_if_missing) throw Error("No enrolled runtime identity exists");
    std::memcpy(state.bytes.data(), identity_magic, sizeof(identity_magic));
    std::memcpy(state.bytes.data() + sizeof(identity_magic), uuid.data(), uuid.size());
    if (RAND_priv_bytes(state.bytes.data() + boot_offset, 64) != 1) {
      throw Error("Cannot generate guest identity");
    }
    state.bytes[key_offset] &= 248;
    state.bytes[key_offset + 31] = (state.bytes[key_offset + 31] & 127) | 64;
    auto digest = state_digest(context, state);
    std::memcpy(state.bytes.data() + context_offset, digest.data(), digest.size());
    auto temporary = ".identity-" + hex(state.bytes.data() + boot_offset, 32);
    Fd file(openat(dir.value, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (file.value < 0) {
      system_error("Cannot create private identity");
    }
    try {
      private_permissions(file.value, false);
      write_all(file.value, {reinterpret_cast<const char *>(state.bytes.data()), state.bytes.size()});
      if (fsync(file.value) != 0) {
        system_error("Cannot persist identity");
      }
      if (linkat(dir.value, temporary.c_str(), dir.value, "identity.bin", 0) != 0) {
        system_error("Cannot install identity without overwriting existing state");
      }
      if (unlinkat(dir.value, temporary.c_str(), 0) != 0 || fsync(dir.value) != 0) {
        system_error("Cannot persist identity directory");
      }
    } catch (...) {
      unlinkat(dir.value, temporary.c_str(), 0);
      throw;
    }
  }
  std::string_view key{reinterpret_cast<const char *>(state.bytes.data() + key_offset), 32};
  Identity identity{hex(state.bytes.data() + boot_offset, 32), derive_wireguard_public_key(key)};
  if (use_key) use_key(lock.value, key);
  return identity;
}
}  // namespace

Identity load_or_create_identity(const Config &config, const std::string &state_dir) {
  return use_identity(config, state_dir);
}

RuntimeIdentity::RuntimeIdentity(const Config &config, const std::string &state_dir, bool create_if_missing) {
  Fd held_lock(-1), key_file(-1);
  identity_ = use_identity(config, state_dir, [&](int lock, std::string_view key) {
    held_lock.value = fcntl(lock, F_DUPFD_CLOEXEC, 10);
    key_file.value = static_cast<int>(syscall(SYS_memfd_create, "cocoon-wg-key", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (held_lock.value < 0 || key_file.value < 0 || fchmod(key_file.value, 0600) != 0) {
      system_error("Cannot protect WireGuard runtime key");
    }
    std::array<unsigned char, 45> encoded{};
    if (EVP_EncodeBlock(encoded.data(), reinterpret_cast<const unsigned char *>(key.data()), 32) != 44) {
      throw Error("Cannot encode WireGuard runtime key");
    }
    encoded[44] = '\n';
    try {
      write_all(key_file.value, {reinterpret_cast<const char *>(encoded.data()), encoded.size()});
    } catch (...) { OPENSSL_cleanse(encoded.data(), encoded.size()); throw; }
    OPENSSL_cleanse(encoded.data(), encoded.size());
    if (lseek(key_file.value, 0, SEEK_SET) < 0 ||
        fcntl(key_file.value, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) {
      system_error("Cannot seal WireGuard runtime key");
    }
  }, create_if_missing);
  lock_fd_ = std::exchange(held_lock.value, -1);
  key_fd_ = std::exchange(key_file.value, -1);
}
RuntimeIdentity::~RuntimeIdentity() {
  if (key_fd_ >= 0) close(key_fd_);
  if (lock_fd_ >= 0) close(lock_fd_);
}

void write_runtime_status(const std::string &state_dir, std::string_view content) {
  if (content.size() > 1024 * 1024) throw Error("Runtime status exceeds limit");
  auto dir = private_directory(state_dir);
  Fd existing(openat(dir.value, "status.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
  if (existing.value >= 0) private_permissions(existing.value, false);
  else if (errno != ENOENT) system_error("Cannot inspect runtime status");
  std::array<unsigned char, 16> random{};
  if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) throw Error("Cannot name runtime status");
  auto name = ".status-" + hex(random.data(), random.size());
  Fd file(openat(dir.value, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (file.value < 0) system_error("Cannot create runtime status");
  try {
    write_all(file.value, content);
    if (fsync(file.value) != 0 || renameat(dir.value, name.c_str(), dir.value, "status.json") != 0 ||
        fsync(dir.value) != 0) system_error("Cannot publish runtime status");
  } catch (...) { unlinkat(dir.value, name.c_str(), 0); throw; }
}

}  // namespace cocoon::wireguard
