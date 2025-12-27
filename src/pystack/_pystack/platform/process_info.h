#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "mem.h"

namespace pystack {

class AbstractProcessInfo
{
  public:
    virtual ~AbstractProcessInfo() = default;

    // Get path to process executable
    virtual std::string getExecutablePath(pid_t pid) const = 0;

    // Get thread name (may return empty if unavailable)
    virtual std::string getThreadName(pid_t pid, int tid) const = 0;

    // Check if process exists
    virtual bool processExists(pid_t pid) const = 0;

    // Get memory maps for process
    virtual std::vector<VirtualMap> getMemoryMaps(pid_t pid) const = 0;
};

}  // namespace pystack
