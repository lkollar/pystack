#pragma once

#include <unordered_set>
#include <vector>

#include <mach/mach.h>

#include "platform/abstract_tracer.h"

namespace pystack {

class DarwinProcessTracer : public AbstractProcessTracer
{
  public:
    // Constructors
    DarwinProcessTracer(pid_t pid);
    DarwinProcessTracer(const DarwinProcessTracer&) = delete;
    DarwinProcessTracer& operator=(const DarwinProcessTracer&) = delete;

    // Destructors
    ~DarwinProcessTracer();

    // Methods
    std::vector<int> getTids() const override;
    void detachFromProcess() override;

  private:
    // Data members
    mach_port_t d_task;
    std::unordered_set<int> d_tids;
};

}  // namespace pystack
