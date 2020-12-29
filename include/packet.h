#pragma once
#include <optional>

#include <bytes/bytes.h>
#include <sys/types.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/socket.h>
#include <netinet/in.h>
#elif defined(_WIN32)
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

using namespace bytes_ns;

namespace pico_sample {

	struct Packet {
		bytes data;
		struct sockaddr_storage addr;
		socklen_t addr_len;

		bool empty() {
			return data.empty();
		}
	};

}
