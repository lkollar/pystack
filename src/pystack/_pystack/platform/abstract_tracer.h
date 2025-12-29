#pragma once

#include <memory>
#include <unistd.h>
#include <vector>

namespace pystack {

class AbstractProcessTracer
{
  public:
    virtual ~AbstractProcessTracer() = default;

    // Return list of thread IDs in the traced process
    virtual std::vector<int> getTids() const = 0;

    // Detach from process (called by destructor)
    virtual void detachFromProcess() = 0;

    static std::shared_ptr<AbstractProcessTracer> create(pid_t pid);
};

}  // namespace pystack
