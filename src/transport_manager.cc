#include <cassert>
#include <iostream>
#include <string.h> // memcpy
#include <thread>

#include "transport_manager.hh"

namespace pico_sample {
TransportManager::TransportManager(const std::string& sfuName_in,
                                   int sfuPort_in)
  : shutDown(false)
  , netTransport(make_transport(this, sfuName_in, sfuPort_in))
{}

TransportManager::~TransportManager()
{
  std::cout << "*************** BAD BAD **********" << std::endl;
  shutDown = true; // tell threads to stop

  if (recvThread.joinable()) {
    recvThread.join();
  }
  if (sendThread.joinable()) {
    sendThread.join();
  }
}

bool
TransportManager::empty()
{
  std::lock_guard<std::mutex> lock(recvQMutex);

  return recvQ.empty();
}

bytes
TransportManager::recv()
{
  bytes data;
  {
    std::lock_guard<std::mutex> lock(recvQMutex);
    if (!recvQ.empty()) {
      data = recvQ.front();
      recvQ.pop();
    }
  }

  return data;
}

void
TransportManager::runNetRecv()
{
  while (!shutDown) {
    bool gotData = netTransport->doRecvs();

    if (!gotData) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }
}

void
TransportManager::runNetSend()
{
  while (!shutDown) {
    if (sendQ.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }
    if (!netTransport->doSends()) {
      // TODO accumulate count and report metric
    }
  }
}

///
/// Client TransportManager
///

ClientTransportManager::ClientTransportManager(std::string sfuName_in,
                                               uint16_t sfuPort_in)
  : TransportManager(sfuName_in, sfuPort_in)
  , sfuName(std::move(sfuName_in))
  , sfuPort(sfuPort_in)
{}

void
ClientTransportManager::start()
{
  netTransport = new NetTransportQUIC(this, sfuName, sfuPort);
  recvThread = std::thread(recvThreadFunc, this);
  sendThread = std::thread(sendThreadFunc, this);
}

ClientTransportManager::~ClientTransportManager() = default;

bool
ClientTransportManager::transport_ready() const
{
  return netTransport->ready();
}

void
ClientTransportManager::send(bytes& data)
{
  {
    std::lock_guard<std::mutex> lock(sendQMutex);
    std::clog << "CP";
    sendQ.push(std::move(data));
    // TODO - check Q not too deep
  }
}

///
/// Server TransportManager
///

ServerTransportManager::ServerTransportManager(int sfuPort)
  : TransportManager("", sfuPort)
{
  assert(netTransport);
  recvThread = std::thread(recvThreadFunc, this);
  sendThread = std::thread(sendThreadFunc, this);
}

ServerTransportManager::~ServerTransportManager() {}

void
ServerTransportManager::send(bytes& data)
{

  {
    std::lock_guard<std::mutex> lock(sendQMutex);
    sendQ.push(std::move(data));
    // TODO - check Q not too deep
  }
}

bool
TransportManager::recvDataFromNet(bytes& data,
                                  struct sockaddr* addr,
                                  socklen_t addrLen)
{
  std::clog << "<";

  {
    std::lock_guard<std::mutex> lock(recvQMutex);
    recvQ.push(data);
    // TODO - check Q not too deep
  }

  return true;
}

std::optional<bytes>
TransportManager::getDataToSendToNet()
{
  if (sendQ.empty()) {
    return std::nullopt;
  }
  // get packet to send from Q
  bytes data;
  {
    std::lock_guard<std::mutex> lock(sendQMutex);
    data = sendQ.front();
    sendQ.pop();
  }

  if (data.empty()) {
    return std::nullopt;
  }

  std::clog << ">";
  return data;
}

} // namespace
