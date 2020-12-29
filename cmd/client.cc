#include <iostream>
#include <bytes/bytes.h>

#include <transport_manager.hh>

using namespace pico_sample;

bool done = false;
ClientTransportManager transportManager("localhost", 5004);

void read_loop() {
	std::cout << "Client read loop init\n";
	while(!done) {
		auto data = transportManager.recv();
		if(!data.empty()) {
			std::cout << "Received: " << to_hex(data) << "\n";
		}
	}
}

int main() {

	const uint8_t forty_bytes[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9};
	while(!transportManager.transport_ready()) {
		std::this_thread::sleep_for(std::chrono::seconds (2));
	}
	std::cout << "Transport is ready" << std::endl;
	std::thread reader (read_loop);

	// Send forty_bytes packet 10 seconds with 50 ms apart

  while(true)
	{
  	auto data = bytes(forty_bytes, forty_bytes+ sizeof(forty_bytes));
		std::cout<< "sending: " << to_hex(data) << std::endl;
		transportManager.send(data);
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return 0;
}
