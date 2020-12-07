#include <cassert>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string.h> // memcpy
#include <thread>
#include <unistd.h>

#if defined(__linux) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netdb.h>
#endif
#if defined(__linux__)
#include <net/ethernet.h>
#include <netpacket/packet.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "netTransportQUIC.hh"
#include "transport_manager.hh"

#include "picoquic.h"
#include "picoquic_binlog.h"
#include "picoquic_internal.h"
#include "picoquic_logger.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"
#include "picoquic_utils.h"
#include "picotls.h"
#include "tls_api.h"

using namespace pico_sample;
#define SIDUCK_ONLY_QUACKS_ECHO 0x101
#define SERVER_CERT_FILE "cert.pem"
#define SERVER_KEY_FILE "key.pem"

static TransportManager* transportManagerGlobalRef;
static NetTransportQUIC* transportGlobalRef;

///
/// Socket Helpers
///

static int
socket_bind_to_port(int sd, int af, int port)
{
  // bind to the port
  struct sockaddr_storage sa;
  int addr_length = 0;
  memset(&sa, 0, sizeof(sa));
  if (af == AF_INET) {
    struct sockaddr_in* s4 = (struct sockaddr_in*)&sa;
    s4->sin_port = port;
    s4->sin_addr.s_addr = INADDR_ANY;
    addr_length = sizeof(struct sockaddr_in);
    return bind(sd, (struct sockaddr*)&sa, addr_length);
  } else {
    assert(af == AF_INET);
  }
  return 0;
}

int
NetTransportQUIC::setup_client_socket(int af)
{
  int sd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
  assert(sd != INVALID_SOCKET);

  // socket options
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 2000; // 2 ms
  int err =
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
  assert(err == 0);

  // bind to port 0 as client
  err = socket_bind_to_port(sd, af, 0);
  assert(err == 0);

  return sd;
}

int
NetTransportQUIC::setup_server_socket(int af, uint16_t port)
{
  int sd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
  assert(sd != INVALID_SOCKET);

  // set for re-use
  int one = 1;
  int err =
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
  assert(err == 0);

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 2000; // 2 ms
  err =
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
  assert(err == 0);

  err = socket_bind_to_port(sd, af, port);
  assert(err == 0);

  return sd;
}

int
transport_close_reason(picoquic_cnx_t* cnx)
{
  uint64_t last_err = 0;
  int ret = 0;
  if ((last_err = picoquic_get_local_error(cnx)) != 0) {
    fprintf(
      stdout, "Connection end with local error 0x%" PRIx64 ".\n", last_err);
    ret = -1;
  }
  if ((last_err = picoquic_get_remote_error(cnx)) != 0) {
    fprintf(
      stdout, "Connection end with remote error 0x%" PRIx64 ".\n", last_err);
    ret = -1;
  }
  if ((last_err = picoquic_get_application_error(cnx)) != 0) {
    fprintf(stdout,
            "Connection end with application error 0x%" PRIx64 ".\n",
            last_err);
    ret = -1;
  }
  return ret;
}

int
NetTransportQUIC::datagram_callback(picoquic_cnx_t* cnx,
                                    uint64_t stream_id,
                                    uint8_t* bytes_in,
                                    size_t length,
                                    picoquic_call_back_event_t fin_or_event,
                                    void* callback_ctx,
                                    void* v_stream_ctx)
{
  int ret = 0;
  datagram_ctx_t* ctx = (pico_sample::datagram_ctx_t*)callback_ctx;
  if (ctx == NULL) {
    ctx = new pico_sample::datagram_ctx_t{};
    ctx->transportManager = transportManagerGlobalRef;
    ctx->transport = transportGlobalRef;
    ctx->transport->cnx_server = cnx;
    if (ctx != NULL) {
      ctx->is_auto_alloc = 1;
    }
    picoquic_set_callback(cnx, &NetTransportQUIC::datagram_callback, ctx);
  } else {
    ret = 0;
  }

  assert(ctx != NULL);

  ret = 0;
  if (ret == 0) {
    switch (fin_or_event) {
      case picoquic_callback_stream_data:
      case picoquic_callback_stream_fin:
      case picoquic_callback_stream_reset: /* Client reset stream #x */
      case picoquic_callback_stop_sending: /* Client asks server to reset stream
                                              #x */
      case picoquic_callback_stream_gap:
      case picoquic_callback_prepare_to_send:
        std::cout << "Unexpected callback " << std::endl;
        if (ctx != NULL) {
          if (ctx->is_auto_alloc) {
            free(ctx);
            ctx = NULL;
          }
        }
        std::cout << "picoquic_callback_prepare_to_send" << std::endl;
        break;
      case picoquic_callback_stateless_reset:
      case picoquic_callback_close:             /* Received connection close */
      case picoquic_callback_application_close: /* Received application close */
        if (ctx != NULL && ctx->is_auto_alloc) {
          free(ctx);
          ctx = NULL;
        }
        std::cout << "picoquic_callback_application_close"
                  << transport_close_reason(cnx) << std::endl;
        picoquic_set_callback(cnx, NULL, NULL);
        assert(0);
        break;
      case picoquic_callback_version_negotiation:
        break;
      case picoquic_callback_almost_ready:
        std::cout << "picoquic_callback_almost_ready" << std::endl;
        break;
      case picoquic_callback_ready: {
        if (ctx->transport) {
          std::cout << " Transport Ready" << std::endl;
          std::lock_guard<std::mutex> lock(
            ctx->transport->quicConnectionReadyMutex);
          ctx->transport->quicConnectionReady = true;
        }
      }
        ret = 0;
        break;
      case picoquic_callback_datagram: {
        /* Process the datagram, which contains an address and a QUIC packet */
        // std::cout << "picoquic_callback_datagram 174" << std::endl;
        // std::string data((char *) bytes, (char *) bytes + length);
        auto data = bytes(bytes_in, bytes_in + length);
        // std::clog <<"rl: " << length << ",";
        std::clog << "Q";
        ctx->transportManager->recvDataFromNet(data, nullptr, 0);
        break;
      }
        ret = 0;
      default:
        assert(0);
        break;
    }
  }

  return ret;
}

static size_t nb_alpn_list = sizeof(alpn_list) / sizeof(picoquic_alpn_list_t);

picoquic_alpn_enum
picoquic_parse_alpn_nz(char const* alpn, size_t len)
{
  picoquic_alpn_enum code = picoquic_alpn_undef;

  if (alpn != NULL) {
    for (size_t i = 0; i < nb_alpn_list; i++) {
      if (memcmp(alpn, alpn_list[i].alpn_val, len) == 0 &&
          alpn_list[i].alpn_val[len] == 0) {
        code = alpn_list[i].alpn_code;
        break;
      }
    }
  }

  return code;
}

int
picoquic_server_callback(picoquic_cnx_t* cnx,
                         uint64_t stream_id,
                         uint8_t* bytes,
                         size_t length,
                         picoquic_call_back_event_t fin_or_event,
                         void* callback_ctx,
                         void* v_stream_ctx)
{
  int ret = 0;
  ret = NetTransportQUIC::datagram_callback(
    cnx, stream_id, bytes, length, fin_or_event, callback_ctx, v_stream_ctx);
  return ret;
}

/* Callback from the TLS stack upon receiving a list of proposed ALPN in the
 * Client Hello */
size_t
picoquic_select_alpn(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count)
{
  size_t ret = count;

  for (size_t i = 0; i < count; i++) {
    if (picoquic_parse_alpn_nz((const char*)list[i].base, list[i].len) !=
        picoquic_alpn_undef) {
      ret = i;
      break;
    }
  }

  return ret;
}

NetTransportQUIC::~NetTransportQUIC()
{
  close();
}

void
NetTransportQUIC::close()
{}

bool
NetTransportQUIC::doRecvs()
{
  return false;
}

bool
NetTransportQUIC::doSends()
{
  return false;
}

int
NetTransportQUIC::quic_start_connection()
{
  // create client connection context
  std::cout << "starting client connection to " << quic_client_ctx.sni
            << std::endl;
  cnx_client =
    picoquic_create_cnx(quicHandle,
                        picoquic_null_connection_id,
                        picoquic_null_connection_id,
                        (struct sockaddr*)&quic_client_ctx.server_address,
                        picoquic_get_quic_time(quicHandle),
                        0,
                        quic_client_ctx.sni.data(),
                        alpn.data(),
                        1);

  assert(cnx_client != nullptr);

  auto* datagram_ctx = new datagram_ctx_t{};
  datagram_ctx->transportManager = transportManager;
  datagram_ctx->transport = this;
  picoquic_set_callback(cnx_client, datagram_callback, (void*)datagram_ctx);
  cnx_client->local_parameters.max_datagram_frame_size = 1500;

  int ret = picoquic_start_client_cnx(cnx_client);
  assert(ret == 0);
  std::cout << "Started Quic Client Connection" << std::endl;
  return ret;
}

// Client Transport
NetTransportQUIC::NetTransportQUIC(TransportManager* t,
                                   std::string sfuName,
                                   uint16_t sfuPort)
  : transportManager(t)
  , m_isServer(false)
  , connectionInitialized(false)
{
  std::cout << "Quic Client Transport" << std::endl;
  // setup UDP socket
  fd = setup_client_socket(AF_INET);

  int ret = picoquic_get_local_address(fd, &local_address);
  assert(ret == 0);

  quic_client_ctx.server_name = sfuName;
  quic_client_ctx.port = sfuPort;
  int is_name = 0;
  ret = picoquic_get_server_address(
    sfuName.c_str(),
    sfuPort,
    reinterpret_cast<sockaddr_storage*>(&quic_client_ctx.server_address),
    &is_name);
  assert(ret == 0);
  quic_client_ctx.server_address_len = sizeof(struct sockaddr_storage);

  // create quic client context
  auto ticket_store_filename = "token-store.bin";

  /* Create QUIC context */
  current_time = picoquic_current_time();
  quicHandle = picoquic_create(1,
                               NULL,
                               NULL,
                               NULL,
                               alpn.data(),
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               current_time,
                               NULL,
                               "ticket-store.bin",
                               NULL,
                               0);

  assert(quicHandle != nullptr);

  picoquic_set_default_congestion_algorithm(quicHandle, picoquic_bbr_algorithm);

  if (picoquic_load_retry_tokens(quicHandle, ticket_store_filename) != 0) {
    fprintf(stderr,
            "No token file present. Will create one as <%s>.\n",
            ticket_store_filename);
  }

  (void)picoquic_set_default_connection_id_length(quicHandle, 8);

  if (picoquic_get_local_address(fd, &local_address) != 0) {
    memset(&local_address, 0, sizeof(struct sockaddr_storage));
    fprintf(stderr, "Could not read local address.\n");
  }
  // start the quic thread
  quicTransportThread = std::thread(quicTransportThreadFunc, this);
}

// server
NetTransportQUIC::NetTransportQUIC(TransportManager* t, uint16_t sfuPort)
  : transportManager(t)
  , m_isServer(true)
  , serverPort(sfuPort)
  , connectionInitialized(false)
{
  std::cout << "Quic Server Transport" << std::endl;
  char default_server_cert_file[512];
  char default_server_key_file[512];
  const char* server_cert_file = nullptr;
  const char* server_key_file = nullptr;

  picoquic_get_input_path(default_server_cert_file,
                          sizeof(default_server_cert_file),
                          "/tmp",
                          SERVER_CERT_FILE);
  server_cert_file = default_server_cert_file;

  picoquic_get_input_path(default_server_key_file,
                          sizeof(default_server_key_file),
                          "/tmp",
                          SERVER_KEY_FILE);
  server_key_file = default_server_key_file;

  current_time = picoquic_current_time();
  quicHandle = picoquic_create(1,
                               server_cert_file,
                               server_key_file,
                               NULL,
                               NULL,
                               picoquic_server_callback,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               current_time,
                               NULL,
                               NULL,
                               NULL,
                               0);

  assert(quicHandle != nullptr);

  picoquic_set_alpn_select_fn(quicHandle, picoquic_select_alpn);
  picoquic_set_default_congestion_algorithm(quicHandle, picoquic_bbr_algorithm);

  picoquic_set_log_level(quicHandle, 2);

  fd = setup_server_socket(AF_INET, sfuPort);
  int ret = picoquic_get_local_address(fd, &local_address);
  assert(ret == 0);

  if (picoquic_get_local_address(fd, &local_address) != 0) {
    memset(&local_address, 0, sizeof(struct sockaddr_storage));
    fprintf(stderr, "Could not read local address.\n");
  }
  quicTransportThread = std::thread(quicTransportThreadFunc, this);
}

// Main quic process thread
// 1. check for incoming packets
// 2. check for outgoing packets
int
NetTransportQUIC::runQuicProcess()
{

  // create the quic connection context
  if (!connectionInitialized && !m_isServer) {
    quic_start_connection();
    connectionInitialized = true;
  } else if (m_isServer) {
    connectionInitialized = true;
  }

  int client_receive_loop = 0;
  int client_send_loop = 0;
  uint64_t curr_time = 0;
  int if_index = -1;
  picoquic_connection_id_t log_cid;
  picoquic_cnx_t* last_cnx = NULL;
  const int dataSize = 1500;

  picoquic_quic_t* quic = quicHandle;

  int ret = 0;
  while (!transportManager->shutDown) {
    std::string buffer(dataSize, 0);
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    socklen_t peer_addr_len = sizeof(peer_addr);
    int rLen = recvfrom(fd,
                        buffer.data(),
                        buffer.size(),
                        0 /*flags*/,
                        (struct sockaddr*)&peer_addr,
                        &peer_addr_len);
    curr_time = picoquic_get_quic_time(quicHandle);
    client_receive_loop++;

    if (rLen > 0) {
      std::cout << "received data " << rLen << " bytes\n";
      buffer.resize(rLen);
      if (local_port == 0) {
        if (picoquic_get_local_address(fd, &local_address) != 0) {
          memset(&local_address, 0, sizeof(struct sockaddr_storage));
          fprintf(stderr, "Could not read local address.\n");
        }
        // todo: support AF_INET6
        local_port = ((struct sockaddr_in*)&local_address)->sin_port;
        std::cout << "Found local port  " << local_port << std::endl;
      }

      // submit the packet
      ret = picoquic_incoming_packet(quic,
                                     reinterpret_cast<uint8_t*>(buffer.data()),
                                     buffer.size(),
                                     (struct sockaddr*)&local_address,
                                     (struct sockaddr*)&peer_addr,
                                     -1,
                                     0,
                                     curr_time);
      assert(ret == 0);
      int send_length = 0;
      std::string send_buffer;
      send_buffer.resize(1536);
      ret = picoquic_prepare_next_packet(
        quicHandle,
        curr_time,
        reinterpret_cast<uint8_t*>(send_buffer.data()),
        send_buffer.size(),
        reinterpret_cast<size_t*>(&send_length),
        reinterpret_cast<sockaddr_storage*>(&peer_addr),
        reinterpret_cast<sockaddr_storage*>(&local_address),
        &if_index,
        &log_cid,
        &last_cnx);

      assert(ret == 0);
      if (ret == PICOQUIC_ERROR_DISCONNECTED) {
        std::cout
          << "PICOQUIC_ERROR_DISCONNECTED: on call to prepare next packet\n";
        ret = 0;
        picoquic_delete_cnx(cnx_client);
        fflush(stdout);
        break;
      }
      if (send_length > 0) {
        std::cout << "prepare_next_packet: send_length " << send_length
                  << std::endl;
        int sock_err = 0;
        int sock_ret =
          picoquic_send_through_socket(fd,
                                       (struct sockaddr*)&peer_addr,
                                       (struct sockaddr*)&local_address,
                                       if_index,
                                       send_buffer.data(),
                                       (int)send_length,
                                       &sock_err);
        assert(sock_err == 0);
      }
    }

    // send loop
    if (rLen == 0 || client_receive_loop > 64) {
      client_receive_loop = 0;
      client_send_loop = 0;
      int send_length = 0;
      int send_timeout_loop_cnt = 0;
      while (client_send_loop < 64) {
        client_send_loop++;
        buffer.clear();
        buffer.reserve(1500);
        auto maybe_data = transportManager->getDataToSendToNet();
        if (!maybe_data.has_value()) {
          if (send_timeout_loop_cnt == 5) {
            break; // move back to the recv loop
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(2));
          send_timeout_loop_cnt++;
          continue;
        }

        if (maybe_data.has_value() && client_send_loop <= 64) {
          // post the datagram
          picoquic_cnx_t* cnx = nullptr;
          if (cnx_client == nullptr) {
            cnx = picoquic_get_earliest_cnx_to_wake(quic, current_time);
          } else {
            cnx = cnx_client;
          }
          auto data = std::move(maybe_data.value());
          std::cout << "enqueueing datagram " << data.size() << std::endl;
          ret = picoquic_queue_datagram_frame(cnx, data.size(), data.data());

          assert(ret == 0);
          send_length = 0;
          ret = picoquic_prepare_next_packet(
            quicHandle,
            curr_time,
            reinterpret_cast<uint8_t*>(buffer.data()),
            buffer.size(),
            reinterpret_cast<size_t*>(&send_length),
            (m_isServer) ? reinterpret_cast<sockaddr_storage*>(&peer_addr)
                         : quic_client_ctx.server_address,
            reinterpret_cast<sockaddr_storage*>(&local_address),
            &if_index,
            &log_cid,
            &last_cnx);

          assert(ret == 0);
          if (ret == PICOQUIC_ERROR_DISCONNECTED) {
            std::cout << "PICOQUIC_ERROR_DISCONNECTED: on call to prepare "
                         "next packet\n";
            ret = 0;
            fflush(stdout);
            break;
          }

          if (send_length > 0) {
            std::cout << "prepare_next_packet (in send loop): send_length "
                      << send_length << std::endl;
            int sock_err = 0;
            int sock_ret =
              picoquic_send_through_socket(fd,
                                           (struct sockaddr*)&peer_addr,
                                           (struct sockaddr*)&local_address,
                                           if_index,
                                           buffer.data(),
                                           (int)send_length,
                                           &sock_err);
            assert(sock_err == 0);
          }
          client_send_loop++;
        }
      } // end while send loop
    }   // send condition
  }     // recv + send loop

  std::cout << "DONE" << std::endl;
  assert(0);
  // return true;
}