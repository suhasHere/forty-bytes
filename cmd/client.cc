#include <iostream>
#include <bytes/bytes.h>

#include <transport_manager.hh>

using namespace pico_sample;

int main() {

	const uint8_t forty_bytes[] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9};
	ClientTransportManager transportManager("localhost", 5004);
	while(!transportManager.transport_ready()) {
		std::this_thread::sleep_for(std::chrono::seconds (2));
	}
	std::cout << "Transport is ready" << std::endl;
	// Send forty_bytes packet 10 seconds with 50 ms apart
	int num_to_send = 40;

  do {
		auto data = bytes(forty_bytes, forty_bytes+ sizeof(forty_bytes));
		transportManager.send(data);
    num_to_send--;
  } while(num_to_send > 0);

  while(1)
	{}


	return 0;
}
