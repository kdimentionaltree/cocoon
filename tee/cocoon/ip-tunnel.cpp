#include "ip-tunnel.h"
#include "tun-device.h"

#include <algorithm>
#include <utility>

#if TD_LINUX
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace cocoon {
namespace {

td::Status validate_packet(td::Slice packet, size_t mtu) {
  if (mtu > 65535 || packet.size() < 20 || packet.size() > mtu) {
    return td::Status::Error("Invalid IPv4 packet length or MTU");
  }
  auto bytes = packet.ubegin();
  auto header_size = (bytes[0] & 15) * 4;
  auto total_size = (static_cast<size_t>(bytes[2]) << 8) | bytes[3];
  if ((bytes[0] >> 4) != 4 || header_size < 20 || static_cast<size_t>(header_size) > packet.size() ||
      total_size != packet.size()) {
    return td::Status::Error("Invalid IPv4 packet header");
  }
  return td::Status::OK();
}

}  // namespace

td::Status encode_packet(td::ChainBufferWriter &output, td::Slice packet, size_t mtu) {
  TRY_STATUS(validate_packet(packet, mtu));
  auto size = static_cast<td::uint32>(packet.size());
  unsigned char header[4]{static_cast<unsigned char>(size >> 24), static_cast<unsigned char>(size >> 16),
                          static_cast<unsigned char>(size >> 8), static_cast<unsigned char>(size)};
  output.append(td::Slice(header, 4));
  output.append(packet);
  return td::Status::OK();
}

td::Result<std::optional<td::BufferSlice>> decode_packet(td::ChainBufferReader &input, size_t mtu) {
  input.sync_with_writer();
  if (input.size() < 4) {
    return std::optional<td::BufferSlice>{};
  }
  auto peek = input.clone();
  unsigned char header[4];
  peek.advance(4, td::MutableSlice(header, 4));
  auto size = (static_cast<td::uint32>(header[0]) << 24) | (static_cast<td::uint32>(header[1]) << 16) |
              (static_cast<td::uint32>(header[2]) << 8) | header[3];
  if (mtu > 65535 || size < 20 || size > mtu) {
    return td::Status::Error("Invalid tunnel frame length");
  }
  if (peek.size() < size) {
    return std::optional<td::BufferSlice>{};
  }
  auto packet = peek.cut_head(size).move_as_buffer_slice();
  TRY_STATUS(validate_packet(packet.as_slice(), mtu));
  input.advance(4 + size);
  return std::optional<td::BufferSlice>{std::move(packet)};
}

IpTunnel::IpTunnel(Config config)
    : config_(std::move(config)), input_(input_writer_.extract_reader()), output_(output_writer_.extract_reader()) {
}

td::Result<IpTunnel::Config> IpTunnel::prepare(TunnelConfig tunnel) {
  TRY_STATUS(validate_tunnel_config(tunnel));
  Config config;
  config.tunnel = std::move(tunnel);
  if (config.tunnel.tunnel_mode == TunnelConfig::TunnelMode::Server) {
    TRY_RESULT(listener, td::ServerSocketFd::open(config.tunnel.listen_port, config.tunnel.listen_host));
    config.listener = std::move(listener);
  } else {
    TRY_STATUS(config.destination.init_host_port(config.tunnel.destination_host, config.tunnel.destination_port));
    if (!config.destination.is_ipv4()) {
      return td::Status::Error("IP tunnel destination must resolve to IPv4");
    }
    if (config.destination.get_ip_str() == config.tunnel.local_ipv4 ||
        config.destination.get_ip_str() == config.tunnel.peer_ipv4) {
      return td::Status::Error("Outer connection must not use a tunnel address");
    }
  }
  TRY_RESULT(device, create_tun_device(config.tunnel.interface));
  config.device = std::move(device);
  return config;
}

#if TD_LINUX
namespace {
bool would_block() {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}
}  // namespace

void IpTunnel::subscribe(td::PollableFdInfo &info) {
  td::actor::SchedulerContext::get().get_poll().subscribe(info.extract_pollable_fd(this), td::PollFlags::ReadWrite());
}

void IpTunnel::start_up() {
  self_ = actor_id(this);
  if (config_.device.empty() || config_.tunnel.mtu < 20 || config_.tunnel.mtu > 65535) {
    return fail(td::Status::Error("Invalid tunnel device or MTU"));
  }
  subscribe(config_.device.get_poll_info());
  tun_subscribed_ = true;
  if (!config_.listener.empty()) {
    subscribe(config_.listener.get_poll_info());
    listener_subscribed_ = true;
    LOG(INFO) << "Tunnel '" << config_.tunnel.name << "' listening on " << config_.tunnel.listen_host << ":"
              << config_.tunnel.listen_port;
  }
  if (!config_.socket.empty()) {
    single_session_ = config_.listener.empty() && !config_.destination.is_valid();
    attach(std::move(config_.socket), false);
  } else if (config_.tunnel.tunnel_mode == TunnelConfig::TunnelMode::Client) {
    connect();
  }
  yield();
}

void IpTunnel::notify() {
  td::actor::send_signals(self_, td::actor::ActorSignals::wakeup());
}

void IpTunnel::attach(td::SocketFd socket, bool connecting) {
  socket_ = std::move(socket);
  socket_.get_poll_info().clear_flags(td::PollFlags::ReadWrite());
  subscribe(socket_.get_poll_info());
  socket_subscribed_ = true;
  state_ = connecting ? State::Connecting : State::Active;
  if (connecting) {
    alarm_timestamp() = td::Timestamp::in(10);
  } else {
    LOG(INFO) << "Tunnel '" << config_.tunnel.name << "' connected (plaintext)";
  }
}

void IpTunnel::connect() {
  auto result = td::SocketFd::open(config_.destination);
  if (result.is_error()) {
    return disconnect(result.move_as_error());
  }
  attach(result.move_as_ok(), true);
}

void IpTunnel::close_socket() {
  if (socket_subscribed_) {
    td::actor::SchedulerContext::get().get_poll().unsubscribe_before_close(socket_.get_poll_info().get_pollable_fd_ref());
    socket_subscribed_ = false;
  }
  socket_.close();
}

void IpTunnel::disconnect(td::Status reason) {
  LOG(WARNING) << "Tunnel '" << config_.tunnel.name << "': " << reason;
  close_socket();
  input_writer_ = td::ChainBufferWriter();
  input_ = input_writer_.extract_reader();
  output_writer_ = td::ChainBufferWriter();
  output_ = output_writer_.extract_reader();
  pending_tun_.clear();
  pending_tun_bytes_ = 0;
  eof_ = false;
  state_ = State::Waiting;
  alarm_timestamp() = td::Timestamp::never();
  if (single_session_) {
    stop();
  } else if (config_.tunnel.tunnel_mode == TunnelConfig::TunnelMode::Client) {
    alarm_timestamp() = td::Timestamp::in(5);
  }
}

void IpTunnel::fail(td::Status reason) {
  LOG(ERROR) << "Tunnel '" << config_.tunnel.name << "': " << reason;
  stop();
  if (config_.on_error) {
    config_.on_error(std::move(reason));
  }
}

void IpTunnel::alarm() {
  if (state_ == State::Connecting) {
    disconnect(td::Status::Error("Connect timed out"));
  } else if (state_ == State::Waiting) {
    connect();
  }
  yield();
}

td::Status IpTunnel::accept_connections() {
  for (size_t i = 0; i < WORK_LIMIT; ++i) {
    auto result = config_.listener.accept();
    if (result.is_error() && result.error().code() == -1) {
      return td::Status::OK();
    }
    TRY_RESULT(socket, std::move(result));
    if (state_ == State::Waiting) {
      attach(std::move(socket), false);
    }  // Other connections close immediately; they cannot replace the active peer.
  }
  yield();
  return td::Status::OK();
}

td::Status IpTunnel::read_tcp() {
  input_.sync_with_writer();
  if (eof_ || pending_tun_bytes_ + config_.tunnel.mtu > BUFFER_LIMIT || pending_tun_.size() >= PACKET_LIMIT) {
    return td::Status::OK();
  }
  size_t budget = std::min(BUFFER_LIMIT - input_.size(), size_t{65536});
  while (budget) {
    auto size = ::recv(socket_.get_native_fd().fd(), scratch_.data(), std::min(budget, scratch_.size()), 0);
    if (size < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (would_block()) {
        socket_.get_poll_info().clear_flags(td::PollFlags::Read());
        break;
      }
      return OS_ERROR("Tunnel TCP read failed");
    }
    if (size == 0) {
      eof_ = true;
      break;
    }
    input_writer_.append(td::Slice(scratch_.data(), size));
    budget -= size;
  }
  if (budget == 0 && input_.size() < BUFFER_LIMIT) {
    yield();
  }
  return td::Status::OK();
}

td::Status IpTunnel::decode_frames() {
  for (size_t i = 0; i < WORK_LIMIT; ++i) {
    if (pending_tun_bytes_ + config_.tunnel.mtu > BUFFER_LIMIT || pending_tun_.size() >= PACKET_LIMIT) {
      return td::Status::OK();
    }
    TRY_RESULT(packet, decode_packet(input_, config_.tunnel.mtu));
    if (!packet) {
      if (eof_ && !input_.empty()) {
        return td::Status::Error("Truncated tunnel frame at EOF");
      }
      return td::Status::OK();
    }
    pending_tun_bytes_ += packet->size();
    pending_tun_.push_back(std::move(*packet));
    ++received_;
  }
  yield();
  return td::Status::OK();
}

td::Status IpTunnel::write_tcp() {
  output_.sync_with_writer();
  bool paused_tun = output_.size() + config_.tunnel.mtu + 4 > BUFFER_LIMIT;
  size_t budget = 65536;
  while (!output_.empty() && budget) {
    auto slice = output_.prepare_read();
    slice.truncate(budget);
    auto size = ::send(socket_.get_native_fd().fd(), slice.data(), slice.size(), MSG_NOSIGNAL);
    if (size < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (would_block()) {
        socket_.get_poll_info().clear_flags(td::PollFlags::Write());
        return td::Status::OK();
      }
      return OS_ERROR("Tunnel TCP write failed");
    }
    if (size == 0) {
      return td::Status::Error("Zero-length TCP write");
    }
    output_.advance(size);
    budget -= size;
    if (paused_tun) {
      // EPOLLET will not repeat the TUN read event when the queue gets space.
      yield();
      paused_tun = false;
    }
  }
  if (!output_.empty()) {
    yield();
  }
  return td::Status::OK();
}

td::Status IpTunnel::read_tun() {
  output_.sync_with_writer();
  for (size_t i = 0; i < WORK_LIMIT; ++i) {
    if (state_ == State::Active && output_.size() + config_.tunnel.mtu + 4 > BUFFER_LIMIT) {
      return td::Status::OK();
    }
    // FileFd::read clears readiness after a short read. TUN short reads are whole
    // packets, so drain using native I/O and clear readiness only on EAGAIN.
    ssize_t size;
    do {
      size = ::read(config_.device.get_native_fd().fd(), scratch_.data(), scratch_.size());
    } while (size < 0 && errno == EINTR);
    if (size < 0) {
      if (would_block()) {
        config_.device.get_poll_info().clear_flags(td::PollFlags::Read());
        return td::Status::OK();
      }
      return OS_ERROR("TUN read failed");
    }
    if (size == 0) {
      return td::Status::Error("TUN device closed");
    }
    if (state_ != State::Active ||
        encode_packet(output_writer_, td::Slice(scratch_.data(), size), config_.tunnel.mtu).is_error()) {
      ++dropped_;
    } else {
      ++sent_;
      output_.sync_with_writer();
    }
  }
  yield();
  return td::Status::OK();
}

td::Status IpTunnel::write_tun() {
  for (size_t i = 0; i < WORK_LIMIT && !pending_tun_.empty(); ++i) {
    auto &packet = pending_tun_.front();
    ssize_t size;
    do {
      size = ::write(config_.device.get_native_fd().fd(), packet.data(), packet.size());
    } while (size < 0 && errno == EINTR);
    if (size < 0) {
      if (would_block()) {
        config_.device.get_poll_info().clear_flags(td::PollFlags::Write());
        return td::Status::OK();
      }
      return OS_ERROR("TUN write failed");
    }
    if (static_cast<size_t>(size) != packet.size()) {
      return td::Status::Error("Short TUN packet write");
    }
    pending_tun_bytes_ -= packet.size();
    pending_tun_.pop_front();
    // Resume decoding/reading even if TCP did not produce another poll edge.
    yield();
  }
  if (!pending_tun_.empty()) {
    yield();
  }
  return td::Status::OK();
}

void IpTunnel::loop() {
  config_.device.get_poll_info().sync_with_poll();
  if (!config_.listener.empty()) {
    config_.listener.get_poll_info().sync_with_poll();
    auto status = accept_connections();
    if (status.is_error()) {
      return fail(std::move(status));
    }
  }
  if (state_ == State::Connecting) {
    auto flags = socket_.get_poll_info().sync_with_poll();
    if (flags.can_write() || flags.can_close() || flags.has_pending_error()) {
      auto status = socket_.get_pending_error();
      if (status.is_error()) {
        disconnect(std::move(status));
      } else {
        state_ = State::Active;
        alarm_timestamp() = td::Timestamp::never();
        LOG(INFO) << "Tunnel '" << config_.tunnel.name << "' connected (plaintext)";
      }
    }
  }
  if (state_ == State::Active) {
    socket_.get_poll_info().sync_with_poll();
    auto device_status = write_tun();
    if (device_status.is_error()) {
      return fail(std::move(device_status));
    }
    auto status = [&]() -> td::Status {
      TRY_STATUS(write_tcp());
      TRY_STATUS(read_tcp());
      TRY_STATUS(decode_frames());
      return td::Status::OK();
    }();
    if (status.is_error()) {
      disconnect(std::move(status));
    } else {
      device_status = write_tun();
      if (device_status.is_error()) {
        return fail(std::move(device_status));
      }
      if (eof_ && input_.empty() && pending_tun_.empty()) {
        disconnect(td::Status::Error("Peer closed connection"));
      }
    }
    if (single_session_ && state_ == State::Waiting) {
      return;
    }
  }
  auto status = read_tun();
  if (status.is_error()) {
    return fail(std::move(status));
  }
  if (state_ == State::Active) {
    status = write_tcp();
    if (status.is_error()) {
      disconnect(std::move(status));
    }
  }
}

void IpTunnel::tear_down() {
  auto &poll = td::actor::SchedulerContext::get().get_poll();
  close_socket();
  if (listener_subscribed_) {
    poll.unsubscribe_before_close(config_.listener.get_poll_info().get_pollable_fd_ref());
    config_.listener.close();
  }
  if (tun_subscribed_) {
    poll.unsubscribe_before_close(config_.device.get_poll_info().get_pollable_fd_ref());
    config_.device.close();
  }
  LOG(INFO) << "Tunnel '" << config_.tunnel.name << "' stopped: sent=" << sent_ << " received=" << received_
            << " dropped=" << dropped_;
}
#else
void IpTunnel::start_up() {
  fail(td::Status::Error("IP tunnels are supported only on Linux"));
}
void IpTunnel::loop() {
}
void IpTunnel::alarm() {
}
void IpTunnel::tear_down() {
}
void IpTunnel::notify() {
}
void IpTunnel::fail(td::Status reason) {
  stop();
  if (config_.on_error) {
    config_.on_error(std::move(reason));
  }
}
#endif

}  // namespace cocoon
