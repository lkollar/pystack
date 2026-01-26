#pragma once

#include <vector>

#include <mach/mach.h>

#include "mem.h"

namespace pystack {

class DarwinProcessMemoryManager : public UnixRemoteMemoryManager
{
  public:
    explicit DarwinProcessMemoryManager(pid_t pid);
    explicit DarwinProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps);

  private:
    mutable mach_port_t d_task;

    ssize_t readChunk(remote_addr_t addr, size_t len, char* dst) const override;
};

}  // namespace pystack
