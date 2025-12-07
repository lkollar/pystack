#include "memory.h"

namespace pystack {

ProcessMemoryManager::ProcessMemoryManager(pid_t pid)
{
}
ProcessMemoryManager::ProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
{
}

ssize_t
ProcessMemoryManager::copyMemoryFromProcess(remote_addr_t addr, size_t size, void* dst) const
{
    return 0;
}

bool
ProcessMemoryManager::isAddressValid(remote_addr_t addr, const VirtualMap& map) const
{
    return false;
}

}  // namespace pystack
