#pragma once

#include <vector>

#include "mem.h"

namespace pystack {

class LinuxProcessMemoryManager : public UnixRemoteMemoryManager
{
  public:
    explicit LinuxProcessMemoryManager(pid_t pid);
    explicit LinuxProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps);

  private:
    pid_t d_pid;
    mutable file_unique_ptr d_memfile;

    ssize_t readChunk(remote_addr_t addr, size_t len, char* dst) const override;
    ssize_t readChunkDirect(remote_addr_t addr, size_t len, char* dst) const;
    ssize_t readChunkThroughMemFile(remote_addr_t addr, size_t len, char* dst) const;
};

}  // namespace pystack
