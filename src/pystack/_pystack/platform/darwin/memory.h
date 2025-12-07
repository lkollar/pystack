#pragma once

#include "../../mem.h"
#include <unistd.h>
#include <vector>

namespace pystack {

class ProcessMemoryManager : public AbstractRemoteMemoryManager
{
  public:
    explicit ProcessMemoryManager(pid_t pid);
    explicit ProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps);

    ssize_t copyMemoryFromProcess(remote_addr_t addr, size_t size, void* dst) const override;
    bool isAddressValid(remote_addr_t addr, const VirtualMap& map) const override;
};

}  // namespace pystack
