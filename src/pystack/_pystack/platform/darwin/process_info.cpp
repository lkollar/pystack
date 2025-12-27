#include "process_info.h"

#include <stdexcept>

namespace pystack {

std::string
DarwinProcessInfo::getExecutablePath(pid_t pid) const
{
    (void)pid;
    throw std::runtime_error("DarwinProcessInfo not implemented");
}

std::string
DarwinProcessInfo::getThreadName(pid_t pid, int tid) const
{
    (void)pid;
    (void)tid;
    throw std::runtime_error("DarwinProcessInfo not implemented");
}

bool
DarwinProcessInfo::processExists(pid_t pid) const
{
    (void)pid;
    throw std::runtime_error("DarwinProcessInfo not implemented");
}

std::vector<VirtualMap>
DarwinProcessInfo::getMemoryMaps(pid_t pid) const
{
    (void)pid;
    throw std::runtime_error("DarwinProcessInfo not implemented");
}

}  // namespace pystack
