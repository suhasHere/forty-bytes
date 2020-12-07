#pragma once

namespace pico_sample {

class NetTransport
{

public:
  virtual bool ready() const = 0;
  virtual void close() = 0;
  virtual bool doSends() = 0;
  virtual bool doRecvs() = 0;
};

} // namespace neo_media