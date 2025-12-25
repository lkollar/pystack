#pragma once

#include <unordered_set>
#include <vector>

#include "platform/abstract_tracer.h"

namespace pystack {

class LinuxProcessTracer : public AbstractProcessTracer
{
  public:
    // Constructors
    LinuxProcessTracer(pid_t pid);
    LinuxProcessTracer(const LinuxProcessTracer&) = delete;
    LinuxProcessTracer& operator=(const LinuxProcessTracer&) = delete;

    // Destructors
    ~LinuxProcessTracer();

    // Methods
    std::vector<int> getTids() const override;
    void detachFromProcess() override;

  private:
    // Data members
    std::unordered_set<int> d_tids;
};

}  // namespace pystack
