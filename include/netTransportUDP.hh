
#pragma once

#include <cassert>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "packet.h"
#include "transport.hh"
#include <picoquic.h>
#include <picoquic_utils.h>

namespace pico_sample {

class NetTransportUDP
{
public:
  // Server Socket
  NetTransportUDP(std::string sfuName_in, uint16_t sfuPort_in);

  // Client Socket
  NetTransportUDP(uint16_t sfuPort_in);

  virtual ~NetTransportUDP();

  bool ready() const;
  void close();
  bool doSends(const Packet& packet);
  bool doRecvs(Packet& packet);

  bool isServer() { return m_isServer; }

  int fd; // UDP socket
  bool m_isServer;
  std::string sfuName;
  uint16_t sfuPort;
  struct sockaddr_storage sfuAddr;
  socklen_t sfuAddrLen;
};

} // namespace neo_media
