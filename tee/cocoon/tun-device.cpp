#include "tun-device.h"

#if TD_LINUX
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#endif

namespace cocoon {

td::Result<td::FileFd> create_tun_device(td::Slice interface_name) {
#if TD_LINUX
  if (interface_name.empty() || interface_name.size() >= IFNAMSIZ || interface_name == "." ||
      interface_name == "..") {
    return td::Status::Error("TUN interface name must be non-empty and at most 15 bytes");
  }
  for (unsigned char c : interface_name) {
    if (c == '\0' || c == '/' || c == ':' || c == '%' || std::isspace(c)) {
      return td::Status::Error("Invalid TUN interface name");
    }
  }

  int raw_fd;
  do {
    raw_fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
  } while (raw_fd < 0 && errno == EINTR);
  if (raw_fd < 0) {
    return OS_ERROR("Failed to open /dev/net/tun");
  }
  td::NativeFd fd(raw_fd);

  struct ifreq request {};
  std::memcpy(request.ifr_name, interface_name.data(), interface_name.size());
  request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
  int result;
  do {
    result = ::ioctl(fd.fd(), TUNSETIFF, &request);
  } while (result < 0 && errno == EINTR);
  if (result < 0) {
    return OS_ERROR(PSLICE() << "Failed to create TUN interface '" << interface_name << "'");
  }
  return td::FileFd::from_native_fd(std::move(fd));
#else
  return td::Status::Error("TUN devices are supported only on Linux");
#endif
}

}  // namespace cocoon
