#pragma once

namespace pico_sample {

class NetTransport
{

public:
  // Indicate if the transport can be used to send/recv
  virtual bool ready() = 0;
  // Close the transport
  virtual void close() = 0;
  // Retrieve the data and send over the network
  virtual bool doSends() = 0;
  // Read the data off the network and save it to the queue
  virtual bool doRecvs() = 0;
};

} // namespace neo_media