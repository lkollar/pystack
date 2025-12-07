#pragma once

#include <sys/types.h>
#include <unordered_set>
#include <vector>

namespace pystack {

class ProcessTracer
{
  public:
    // Constructors
    ProcessTracer(pid_t pid);
    ProcessTracer(const ProcessTracer&) = delete;
    ProcessTracer& operator=(const ProcessTracer&) = delete;

    // Destructors
    ~ProcessTracer();

    // Methods
    std::vector<int> getTids() const;

  private:
    // Data members
    std::unordered_set<int> d_tids;

    // Methods
    void detachFromProcess();
};

}  // namespace pystack
