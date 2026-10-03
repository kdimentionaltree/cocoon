#pragma once

#include "td/utils/port/FileFd.h"

namespace cocoon {

// Create a new Linux TUN interface. The returned nonblocking, close-on-exec
// descriptor owns the nonpersistent device; closing it removes the interface.
// An existing interface is an error. Addresses, MTU and routes are configured separately.
td::Result<td::FileFd> create_tun_device(td::Slice interface_name);

}  // namespace cocoon
