#pragma once

#include <cassert>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <thread>

#include <bytes/bytes.h>

#include "netTransportQUIC.hh"
#include "packet.h"
#include "transport.hh"

using namespace bytes_ns;
namespace pico_sample {

class TransportManager
{
public:
  static NetTransport* make_transport(TransportManager* transportManager,
                                      const std::string& sfuName_in,
                                      int sfuPort_in)
  {
    if (sfuName_in.empty()) {
      // server
      return new NetTransportQUIC(transportManager, sfuPort_in);
    } else {
      // client
      return new NetTransportQUIC(transportManager, sfuName_in, sfuPort_in);
    }
  }

  enum Type
  {
    Client,
    Server
  };

  virtual Type type() const = 0;

  TransportManager(const std::string& sfuName_in, int sfuPort_in);

  virtual bool transport_ready() const = 0;

  virtual void send(bytes& app_data) = 0;

  bool empty();

  bytes recv();

  virtual bool recvDataFromNet(bytes& data_in,
                               struct sockaddr* addr,
                               socklen_t addrLen);

  virtual std::optional<bytes> getDataToSendToNet();

  bool shutDown;

protected:
  friend NetTransport;
  NetTransport* netTransport;

  virtual ~TransportManager();

  void runNetRecv();

  std::queue<bytes> recvQ;
  std::mutex recvQMutex;
  std::thread recvThread;
  static int recvThreadFunc(TransportManager* t)
  {
    assert(t);
    t->runNetRecv();
    return 0;
  }

  void runNetSend();
  std::queue<bytes> sendQ;
  std::mutex sendQMutex;
  std::thread sendThread;
  static int sendThreadFunc(TransportManager* t)
  {
    assert(t);
    t->runNetSend();
    return 0;
  }
};

class ClientTransportManager : public TransportManager
{
public:
  ClientTransportManager(std::string sfuName_in, uint16_t sfuPort_in);

  virtual ~ClientTransportManager();

  void start();

  virtual Type type() const { return Type::Client; }

  virtual bool transport_ready() const;

  virtual void send(bytes& data);

private:
  std::string sfuName;
  uint16_t sfuPort;
};

class ServerTransportManager : public TransportManager
{
public:
  ServerTransportManager(int sfuPort = 5004);
  virtual ~ServerTransportManager();
  virtual Type type() const { return Type::Server; }

  virtual bool transport_ready() const { return netTransport->ready(); }

  virtual void send(bytes& data);
};

} // namespace neo_media
