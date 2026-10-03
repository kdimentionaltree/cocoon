#pragma once

#include "ProxyConfig.h"
#include "td/actor/actor.h"
#include "td/utils/Observer.h"
#include "td/utils/buffer.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/ServerSocketFd.h"

#include <array>
#include <deque>
#include <functional>
#include <optional>

namespace cocoon {

td::Status encode_packet(td::ChainBufferWriter &output, td::Slice packet, size_t mtu);
// Empty optional means incomplete input. Incomplete or invalid frames are not consumed.
td::Result<std::optional<td::BufferSlice>> decode_packet(td::ChainBufferReader &input, size_t mtu);

class IpTunnel final : public td::actor::Actor, private td::ObserverBase {
 public:
  struct Config {
    TunnelConfig tunnel;
    td::FileFd device;
    td::ServerSocketFd listener;
    td::IPAddress destination;
    // An already connected stream can also be supplied, e.g. by a session initializer.
    td::SocketFd socket;
    std::function<void(td::Status)> on_error;
  };

  // Called outside the actor: resolve the endpoint, bind the listener and create TUN.
  // Address, MTU and route configuration remains separate from device creation.
  static td::Result<Config> prepare(TunnelConfig tunnel);
  explicit IpTunnel(Config config);

 private:
  static constexpr size_t BUFFER_LIMIT = 1 << 20;
  static constexpr size_t PACKET_LIMIT = 4096;
  static constexpr size_t WORK_LIMIT = 64;
  enum class State { Waiting, Connecting, Active } state_{State::Waiting};
  Config config_;
  td::actor::ActorId<IpTunnel> self_;
  td::SocketFd socket_;
  td::ChainBufferWriter input_writer_, output_writer_;
  td::ChainBufferReader input_, output_;
  std::deque<td::BufferSlice> pending_tun_;
  size_t pending_tun_bytes_{0};
  std::array<char, 65536> scratch_;
  bool tun_subscribed_{false}, listener_subscribed_{false}, socket_subscribed_{false};
  bool eof_{false}, single_session_{false};
  size_t sent_{0}, received_{0}, dropped_{0};

  void start_up() final;
  void loop() final;
  void alarm() final;
  void tear_down() final;
  void notify() final;
  void subscribe(td::PollableFdInfo &info);
  void close_socket();
  void attach(td::SocketFd socket, bool connecting);
  void connect();
  void disconnect(td::Status reason);
  void fail(td::Status reason);
  td::Status accept_connections();
  td::Status read_tcp();
  td::Status decode_frames();
  td::Status write_tcp();
  td::Status read_tun();
  td::Status write_tun();
};

}  // namespace cocoon
