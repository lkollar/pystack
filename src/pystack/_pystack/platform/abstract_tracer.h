#pragma once

#include <vector>
#include <unistd.h>

namespace pystack {

class AbstractProcessTracer
{
  public:
    virtual ~AbstractProcessTracer() = default;

    // Return list of thread IDs in the traced process
    virtual std::vector<int> getTids() const = 0;

    // Detach from process (called by destructor)
    virtual void detachFromProcess() = 0;
};

}  // namespace pystack
