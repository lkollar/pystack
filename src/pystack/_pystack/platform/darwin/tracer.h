#pragma once

#include <unistd.h>
#include <unordered_set>
#include <vector>

namespace pystack {

class ProcessTracer
{
  public:
    ProcessTracer(pid_t pid);
    ~ProcessTracer();

    std::vector<int> getTids() const;

  private:
    std::unordered_set<int> d_tids;
    void detachFromProcess();
};

}  // namespace pystack
