#pragma once

#include "platform/process_info.h"

namespace pystack {

std::vector<VirtualMap>
parseProcMaps(const std::string& content);

class LinuxProcessInfo : public AbstractProcessInfo
{
  public:
    std::string getExecutablePath(pid_t pid) const override;
    std::string getThreadName(pid_t pid, int tid) const override;
    bool processExists(pid_t pid) const override;
    std::vector<VirtualMap> getMemoryMaps(pid_t pid) const override;
};

}  // namespace pystack
