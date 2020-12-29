
#include <iostream>

#include "transport_manager.hh"

using namespace pico_sample;

int main()
{
    ServerTransportManager transport;

    while (1)
    {
        if (transport.empty())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        bytes data = transport.recv();
        std::clog << "Received " << to_hex(data) << "\n";
        transport.send(data);
    }

    return 0;
}
