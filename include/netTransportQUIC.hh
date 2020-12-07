
#pragma once

#include <cassert>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "transport.hh"

#include <picoquic.h>
#include <picoquic_utils.h>

namespace pico_sample {

class TransportManager;

class NetTransportQUIC;

typedef struct st_datagram_ctx_t
{
  int is_auto_alloc;
  TransportManager* transportManager;
  NetTransportQUIC* transport;
} datagram_ctx_t;

typedef enum
{
  picoquic_alpn_undef = 0,
  picoquic_alpn_http_0_9,
  picoquic_alpn_http_3,
  picoquic_alpn_siduck
} picoquic_alpn_enum;

typedef struct st_picoquic_alpn_list_t
{
  picoquic_alpn_enum alpn_code;
  char const* alpn_val;
} picoquic_alpn_list_t;

static picoquic_alpn_list_t alpn_list[] = {
  { picoquic_alpn_http_3, "h3-32" },  { picoquic_alpn_http_0_9, "hq-32" },
  { picoquic_alpn_http_3, "h3-31" },  { picoquic_alpn_http_0_9, "hq-31" },
  { picoquic_alpn_http_3, "h3-29" },  { picoquic_alpn_http_0_9, "hq-29" },
  { picoquic_alpn_http_3, "h3-30" },  { picoquic_alpn_http_0_9, "hq-30" },
  { picoquic_alpn_http_3, "h3-28" },  { picoquic_alpn_http_0_9, "hq-28" },
  { picoquic_alpn_http_3, "h3-27" },  { picoquic_alpn_http_0_9, "hq-27" },
  { picoquic_alpn_http_3, "h3" },     { picoquic_alpn_http_0_9, "hq" },
  { picoquic_alpn_siduck, "siduck" }, { picoquic_alpn_siduck, "siduck-00" }
};

class NetTransportQUIC : public NetTransport
{
public:
  NetTransportQUIC(TransportManager*,
                   std::string sfuName_in,
                   uint16_t sfuPort_in);
  NetTransportQUIC(TransportManager*, uint16_t sfuPort_in);
  virtual ~NetTransportQUIC();

  virtual bool ready() const { return connectionInitialized; }
  virtual void close();
  virtual bool doSends();
  virtual bool doRecvs();

  int runQuicProcess();

  static int datagram_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id,
                               uint8_t* bytes,
                               size_t length,
                               picoquic_call_back_event_t fin_or_event,
                               void* callback_ctx,
                               void* v_stream_ctx);

  std::thread quicThread;
  static int quicThreadFunc(NetTransportQUIC* netTransportQuic, bool is_server)
  {
    if (is_server) {
      return netTransportQuic->start_server_transport();
    } else {
      return netTransportQuic->start_client_transport();
    }
  }

  int start_client_transport();
  int start_server_transport();

  TransportManager* transportManager;

  std::mutex quicConnectionReadyMutex;
  bool quicConnectionReady;
  std::thread quicSendDataThread;
  static int quicSendDataThreadFunc(NetTransportQUIC* netTransportQuic)
  {
    return netTransportQuic->doSends();
  }
  // one thread to rule them all
  std::thread quicTransportThread;
  static int quicTransportThreadFunc(NetTransportQUIC* netTransportQuic)
  {
    return netTransportQuic->runQuicProcess();
  }

  struct QuicClientContext
  {
    std::string server_name;
    uint16_t port;
    std::string sni;
    struct sockaddr_storage* server_address;
    socklen_t server_address_len;
  };

protected:
  const bool m_isServer;

private:
  // Kick start Quic's connection context
  int quic_start_connection();

  int setup_client_socket(int af);
  int setup_server_socket(int af, uint16_t port);

  QuicClientContext quic_client_ctx;

  std::string alpn = "proto-pq-sample";
  picoquic_quic_t* quicHandle = nullptr;
  picoquic_cnx_t* quicConnectionHandler = nullptr;
  sockaddr_storage local_address;
  uint16_t local_port = 0;

  uint64_t current_time = 0;
  int fd;
  uint16_t serverPort;
  // make it state
  bool connectionInitialized;

  picoquic_cnx_t* cnx_client = nullptr;
  picoquic_cnx_t* cnx_server = nullptr;
};

} // namespace neo_media
