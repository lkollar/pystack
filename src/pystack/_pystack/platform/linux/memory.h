#pragma once

#include <unistd.h>
#include <vector>

#include "../../mem.h"

namespace pystack {

class ProcessMemoryManager : public AbstractRemoteMemoryManager
{
    // Constructors
  public:
    explicit ProcessMemoryManager(pid_t pid);
    explicit ProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps);

    // Methods
    ssize_t copyMemoryFromProcess(remote_addr_t addr, size_t size, void* dst) const override;
    bool isAddressValid(remote_addr_t addr, const VirtualMap& map) const override;

  private:
    // Data members
    pid_t d_pid;
    std::vector<VirtualMap> d_vmaps;
    mutable LRUCache d_lru_cache;
    mutable file_unique_ptr d_memfile;

    // Methods
    ssize_t readChunk(remote_addr_t addr, size_t len, char* dst) const;
    ssize_t readChunkDirect(remote_addr_t addr, size_t len, char* dst) const;
    ssize_t readChunkThroughMemFile(remote_addr_t addr, size_t len, char* dst) const;
};

}  // namespace pystack
