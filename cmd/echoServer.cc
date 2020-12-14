
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
        std::clog << "Received " << data.size() << " bytes\n";
    }

    return 0;
}
