#include "cocoon/ip-tunnel.h"
#include "td/utils/tests.h"

#include <string>
#include <vector>

#if TD_LINUX
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
std::string packet(size_t size = 64, unsigned char marker = 7) {
  std::string result(size, static_cast<char>(marker));
  result[0] = 0x45;
  result[2] = static_cast<char>(size >> 8);
  result[3] = static_cast<char>(size);
  return result;
}

std::string frame(td::Slice value) {
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  cocoon::encode_packet(writer, value, 1400).ensure();
  reader.sync_with_writer();
  return reader.move_as_buffer_slice().as_slice().str();
}
}  // namespace

TEST(IpTunnel, CodecSplitAndCoalescedFrames) {
  auto value = packet(1400);
  auto encoded = frame(value);
  ASSERT_EQ(encoded.size(), 1404u);
  ASSERT_EQ(static_cast<unsigned char>(encoded[0]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(encoded[1]), 0u);
  ASSERT_EQ(static_cast<unsigned char>(encoded[2]), 5u);
  ASSERT_EQ(static_cast<unsigned char>(encoded[3]), 120u);
  for (size_t split = 0; split < encoded.size(); ++split) {
    td::ChainBufferWriter writer;
    auto reader = writer.extract_reader();
    writer.append(td::Slice(encoded).substr(0, split));
    ASSERT_TRUE(!cocoon::decode_packet(reader, 1400).move_as_ok());
    ASSERT_EQ(reader.size(), split);
    writer.append(td::Slice(encoded).substr(split));
    writer.append(encoded);
    for (int i = 0; i < 2; ++i) {
      auto decoded = cocoon::decode_packet(reader, 1400).move_as_ok();
      ASSERT_TRUE(decoded.has_value());
      ASSERT_EQ(decoded->as_slice(), td::Slice(value));
    }
    ASSERT_TRUE(reader.empty());
  }
  // Force both the header and payload across ChainBuffer chunks.
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  for (char byte : encoded) {
    writer.append(td::BufferSlice(td::Slice(&byte, 1)));
  }
  ASSERT_EQ(cocoon::decode_packet(reader, 1400).move_as_ok()->as_slice(), td::Slice(value));
}

TEST(IpTunnel, CodecRejectsMalformedFrames) {
  for (unsigned int length : {0u, 19u, 1401u, 65536u, 0xffffffffu}) {
    unsigned char header[4]{static_cast<unsigned char>(length >> 24), static_cast<unsigned char>(length >> 16),
                            static_cast<unsigned char>(length >> 8), static_cast<unsigned char>(length)};
    td::ChainBufferWriter writer;
    auto reader = writer.extract_reader();
    writer.append(td::Slice(header, 4));
    ASSERT_TRUE(cocoon::decode_packet(reader, 1400).is_error());
    ASSERT_EQ(reader.size(), 4u);
  }
  for (int kind = 0; kind < 5; ++kind) {
    auto value = packet();
    auto encoded = frame(value);
    switch (kind) {
      case 0: encoded[4] = 0x65; break;  // IPv6
      case 1: encoded[4] = 0x44; break;  // Too small IHL
      case 2: encoded[4] = 0x4f; encoded.resize(24); encoded[3] = 20; break;  // IHL exceeds packet
      case 3: encoded[7] = 63; break;  // Total length mismatch
      case 4: encoded[6] = 1; break;
    }
    td::ChainBufferWriter writer;
    auto reader = writer.extract_reader();
    writer.append(encoded);
    ASSERT_TRUE(cocoon::decode_packet(reader, 1400).is_error());
    ASSERT_EQ(reader.size(), encoded.size());
  }
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  ASSERT_TRUE(cocoon::encode_packet(writer, packet(1401), 1400).is_error());
  reader.sync_with_writer();
  ASSERT_TRUE(reader.empty());
  auto value = packet();
  value[0] = 0x46;  // Options and fragmentation are allowed.
  value[6] = 0x20;
  cocoon::encode_packet(writer, value, 1400).ensure();
  ASSERT_EQ(cocoon::decode_packet(reader, 1400).move_as_ok()->as_slice(), td::Slice(value));
}

#if TD_LINUX
namespace {
std::pair<td::NativeFd, td::NativeFd> socket_pair(int type) {
  int fds[2];
  CHECK(::socketpair(AF_UNIX, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) == 0);
  return {td::NativeFd(fds[0]), td::NativeFd(fds[1])};
}

struct Session {
  enum class Mode { Connected, Client, Server };
  td::actor::Scheduler scheduler{{0}};
  td::actor::ActorOwn<cocoon::IpTunnel> actor;
  td::ServerSocketFd listener;
  td::IPAddress endpoint;
  td::NativeFd device, transport;
  int owned_device{-1}, owned_transport{-1};
  bool failed{false};

  explicit Session(Mode mode = Mode::Connected) {
    auto devices = socket_pair(SOCK_DGRAM);
    owned_device = devices.first.fd();
    device = std::move(devices.second);
    cocoon::IpTunnel::Config config;
    config.tunnel.name = "test";
    config.device = td::FileFd::from_native_fd(std::move(devices.first));
    if (mode == Mode::Connected) {
      auto streams = socket_pair(SOCK_STREAM);
      owned_transport = streams.first.fd();
      transport = std::move(streams.second);
      config.socket = td::SocketFd::from_native_fd(std::move(streams.first)).move_as_ok();
    } else {
      for (int port = 28000; port < 28100; ++port) {
        auto result = td::ServerSocketFd::open(port, "127.0.0.1");
        if (result.is_ok()) {
          listener = result.move_as_ok();
          endpoint.init_host_port("127.0.0.1", port).ensure();
          config.tunnel.listen_host = "127.0.0.1";
          config.tunnel.listen_port = port;
          break;
        }
      }
      CHECK(!listener.empty());
      if (mode == Mode::Server) {
        config.tunnel.tunnel_mode = cocoon::TunnelConfig::TunnelMode::Server;
        config.listener = std::move(listener);
      } else {
        config.destination = endpoint;
      }
    }
    config.on_error = [&](td::Status) { failed = true; };
    scheduler.run_in_context([&] {
      actor = td::actor::create_actor<cocoon::IpTunnel>(
          td::actor::ActorOptions().with_name("TestTunnel").with_poll(true), std::move(config));
    });
    scheduler.start();
    step();
    if (mode == Mode::Server) {
      connect_peer();
    } else if (mode == Mode::Client) {
      accept_peer();
    }
  }
  ~Session() {
    scheduler.run_in_context([&] { actor.reset(); });
    step();
    scheduler.stop();
    scheduler.run();
  }
  void step() { scheduler.run(0.001); }
  void connect_peer() {
    auto peer = td::SocketFd::open(endpoint).move_as_ok();
    transport = td::NativeFd(::fcntl(peer.get_native_fd().fd(), F_DUPFD_CLOEXEC, 0));
    CHECK(transport);
    for (int i = 0; i < 5; ++i) {
      step();
    }
  }
  void accept_peer() {
    for (int i = 0; i < 10000; ++i) {
      auto result = listener.accept();
      if (result.is_ok()) {
        auto peer = result.move_as_ok();
        transport = td::NativeFd(::fcntl(peer.get_native_fd().fd(), F_DUPFD_CLOEXEC, 0));
        CHECK(transport);
        step();
        return;
      }
      CHECK(result.error().code() == -1);
      step();
    }
    CHECK(false);
  }
  void send_frame(td::Slice bytes) {
    size_t offset = 0;
    for (int i = 0; offset < bytes.size() && i < 2000; ++i) {
      auto count = ::send(transport.fd(), bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
      if (count > 0) {
        offset += static_cast<size_t>(count);
      } else {
        if (!(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
          LOG(FATAL) << "send=" << count << " errno=" << errno << " fd=" << transport.fd();
        }
      }
      step();
    }
    ASSERT_EQ(offset, bytes.size());
  }
  std::string receive_packet() {
    char data[65536];
    for (int i = 0; i < 2000; ++i) {
      auto count = ::recv(device.fd(), data, sizeof(data), 0);
      if (count >= 0) {
        return std::string(data, static_cast<size_t>(count));
      }
      CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      step();
    }
    CHECK(false);
    return {};
  }
};
}  // namespace

TEST(IpTunnel, ActorPacketBoundariesAndPartialFrames) {
  Session session;
  auto value = packet();
  auto encoded = frame(value);
  session.send_frame(td::Slice(encoded).substr(0, 3));
  char data[65536];
  ASSERT_TRUE(::recv(session.device.fd(), data, sizeof(data), 0) < 0 && errno == EAGAIN);
  session.send_frame(td::Slice(encoded).substr(3));
  ASSERT_EQ(session.receive_packet(), value);
  for (unsigned char marker = 1; marker <= 50; ++marker) {
    auto outgoing = packet(100, marker);
    CHECK(::send(session.device.fd(), outgoing.data(), outgoing.size(), MSG_NOSIGNAL) == 100);
  }
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  unsigned char expected = 1;
  for (int i = 0; expected <= 50 && i < 2000; ++i) {
    session.step();
    auto count = ::recv(session.transport.fd(), data, sizeof(data), 0);
    if (count > 0) {
      writer.append(td::Slice(data, count));
    }
    while (auto decoded = cocoon::decode_packet(reader, 1400).move_as_ok()) {
      ASSERT_EQ(decoded->as_slice(), td::Slice(packet(100, expected++)));
    }
  }
  ASSERT_EQ(expected, 51);
  ASSERT_TRUE(!session.failed);
}

TEST(IpTunnel, ActorBackpressureResumesWithoutNewEdge) {
  Session session;
  auto value = packet(1400);
  auto encoded = frame(value);
  std::string frames;
  for (int i = 0; i < 1300; ++i) {
    frames += encoded;
  }
  // Fill the packet device and actor's inbound queues until the producer blocks.
  size_t offset = 0;
  int blocked = 0;
  while (blocked < 20 && offset < frames.size()) {
    auto count = ::send(session.transport.fd(), frames.data() + offset, frames.size() - offset, MSG_NOSIGNAL);
    if (count > 0) {
      offset += static_cast<size_t>(count);
      blocked = 0;
    } else {
      CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      ++blocked;
    }
    session.step();
  }
  ASSERT_TRUE(offset < frames.size());
  auto reverse = packet(100, 42);
  CHECK(::send(session.device.fd(), reverse.data(), reverse.size(), MSG_NOSIGNAL) == 100);
  char data[65536];
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  bool reversed = false;
  for (int i = 0; !reversed && i < 2000; ++i) {
    session.step();
    auto count = ::recv(session.transport.fd(), data, sizeof(data), 0);
    if (count > 0) {
      writer.append(td::Slice(data, count));
    }
    auto decoded = cocoon::decode_packet(reader, 1400).move_as_ok();
    if (decoded) {
      ASSERT_EQ(decoded->as_slice(), td::Slice(reverse));
      reversed = true;
    }
  }
  ASSERT_TRUE(reversed);
  int received = 0;
  for (int i = 0; received < 1300 && i < 10000; ++i) {
    if (offset < frames.size()) {
      auto count = ::send(session.transport.fd(), frames.data() + offset, frames.size() - offset, MSG_NOSIGNAL);
      if (count > 0) {
        offset += static_cast<size_t>(count);
      } else {
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      }
    }
    for (;;) {
      auto count = ::recv(session.device.fd(), data, sizeof(data), 0);
      if (count < 0) {
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
        break;
      }
      ASSERT_EQ(td::Slice(data, count), td::Slice(value));
      ++received;
    }
    session.step();
  }
  ASSERT_EQ(received, 1300);
  ASSERT_EQ(offset, frames.size());
  ASSERT_TRUE(!session.failed);
}

TEST(IpTunnel, ActorInvalidFrameAndDescriptorCleanup) {
  Session session;
  std::string invalid(4, '\0');
  session.send_frame(invalid);
  for (int i = 0; i < 10; ++i) {
    session.step();
  }
  ASSERT_EQ(::fcntl(session.owned_device, F_GETFD), -1);
  ASSERT_EQ(::fcntl(session.owned_transport, F_GETFD), -1);
}

TEST(IpTunnel, ActorOutboundBackpressure) {
  Session session;
  auto value = packet(1400);
  int sent = 0;
  int blocked = 0;
  while (sent < 1300 && blocked < 20) {
    auto count = ::send(session.device.fd(), value.data(), value.size(), MSG_NOSIGNAL);
    if (count >= 0) {
      ASSERT_EQ(count, 1400);
      ++sent;
      blocked = 0;
    } else {
      CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      ++blocked;
    }
    session.step();
  }
  ASSERT_TRUE(sent < 1300);
  auto reverse = packet(100, 42);
  session.send_frame(frame(reverse));
  ASSERT_EQ(session.receive_packet(), reverse);

  char data[65536];
  td::ChainBufferWriter writer;
  auto reader = writer.extract_reader();
  int received = 0;
  for (int i = 0; received < 1300 && i < 10000; ++i) {
    if (sent < 1300) {
      auto count = ::send(session.device.fd(), value.data(), value.size(), MSG_NOSIGNAL);
      if (count >= 0) {
        ASSERT_EQ(count, 1400);
        ++sent;
      } else {
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      }
    }
    auto count = ::recv(session.transport.fd(), data, sizeof(data), 0);
    if (count > 0) {
      writer.append(td::Slice(data, count));
    } else {
      CHECK(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    }
    while (auto decoded = cocoon::decode_packet(reader, 1400).move_as_ok()) {
      ASSERT_EQ(decoded->as_slice(), td::Slice(value));
      ++received;
    }
    session.step();
  }
  ASSERT_EQ(received, 1300);
  ASSERT_EQ(sent, 1300);
  ASSERT_TRUE(!session.failed);
}

TEST(IpTunnel, ActorClientServerReconnect) {
  for (auto mode : {Session::Mode::Client, Session::Mode::Server}) {
    Session session(mode);
    auto value = packet();
    session.send_frame(frame(value));
    ASSERT_EQ(session.receive_packet(), value);
    if (mode == Session::Mode::Server) {
      auto extra = td::SocketFd::open(session.endpoint).move_as_ok();
      for (int i = 0; i < 10; ++i) {
        session.step();
      }
      char byte;
      ASSERT_EQ(::recv(extra.get_native_fd().fd(), &byte, 1, 0), 0);
      // The rejected second connection must leave the first session usable.
      session.send_frame(frame(value));
      ASSERT_EQ(session.receive_packet(), value);
    }
    // Drop a partial frame with the session; it must not contaminate the next one.
    session.send_frame(td::Slice(frame(value)).substr(0, 5));
    session.transport.close();
    for (int i = 0; i < 10; ++i) {
      session.step();
    }
    ASSERT_TRUE(::fcntl(session.owned_device, F_GETFD) >= 0);
    if (mode == Session::Mode::Server) {
      session.connect_peer();
    } else {
      session.accept_peer();
    }
    session.send_frame(frame(value));
    ASSERT_EQ(session.receive_packet(), value);
    ASSERT_TRUE(!session.failed);
  }
}
#endif
