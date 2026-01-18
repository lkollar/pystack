#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "platform/core_file.h"

namespace pystack {

class DwflCoreFileAnalyzer;

class CoreAnalyzerError : public std::exception
{
  public:
    explicit CoreAnalyzerError(std::string error)
    : d_error(std::move(error))
    {
    }

    [[nodiscard]] const char* what() const noexcept override
    {
        return d_error.c_str();
    }

  private:
    std::string d_error;
};

class LinuxCoreFileExtractor : public AbstractCoreFileExtractor
{
  public:
    explicit LinuxCoreFileExtractor(std::shared_ptr<AbstractCoreFileAnalyzer> analyzer);

    std::vector<CoreVirtualMap> MemoryMaps() const override;
    std::vector<SimpleVirtualMap> ModuleInformation() const override;
    pid_t Pid() const override;
    std::string extractExecutable() const override;
    CoreCrashInfo extractFailureInfo() const override;
    CorePsInfo extractPSInfo() const override;
    std::vector<CoreVirtualMap> extractMappedFiles() const override;
    std::vector<std::string> missingModules() const override;

  private:
    void populateMaps();
    uintptr_t findExecFn() const;

    std::shared_ptr<AbstractCoreFileAnalyzer> d_analyzer;
    std::shared_ptr<DwflCoreFileAnalyzer> d_dwfl_analyzer;
    std::vector<SimpleVirtualMap> d_module_info;
    std::vector<CoreVirtualMap> d_maps;
};

}  // namespace pystack
