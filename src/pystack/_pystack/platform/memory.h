#pragma once

#include <memory>

#include "mem.h"

namespace pystack {

std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid);
std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps);

}  // namespace pystack
