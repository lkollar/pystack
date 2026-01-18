#pragma once

#include <memory>

#include "platform/core_file.h"

namespace pystack {

class DarwinCoreFileExtractor : public AbstractCoreFileExtractor
{
  public:
    explicit DarwinCoreFileExtractor(std::shared_ptr<AbstractCoreFileAnalyzer> analyzer);

    std::vector<CoreVirtualMap> MemoryMaps() const override;
    std::vector<SimpleVirtualMap> ModuleInformation() const override;
    pid_t Pid() const override;
    std::string extractExecutable() const override;
    CoreCrashInfo extractFailureInfo() const override;
    CorePsInfo extractPSInfo() const override;
    std::vector<CoreVirtualMap> extractMappedFiles() const override;
    std::vector<std::string> missingModules() const override;
};

}  // namespace pystack
