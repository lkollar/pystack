#include "platform/darwin/core_file.h"

#include <stdexcept>
#include <utility>

namespace pystack {

DarwinCoreFileExtractor::DarwinCoreFileExtractor(
        std::shared_ptr<AbstractCoreFileAnalyzer> /* analyzer */)
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::vector<CoreVirtualMap>
DarwinCoreFileExtractor::MemoryMaps() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::vector<SimpleVirtualMap>
DarwinCoreFileExtractor::ModuleInformation() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

pid_t
DarwinCoreFileExtractor::Pid() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::string
DarwinCoreFileExtractor::extractExecutable() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

CoreCrashInfo
DarwinCoreFileExtractor::extractFailureInfo() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

CorePsInfo
DarwinCoreFileExtractor::extractPSInfo() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::vector<CoreVirtualMap>
DarwinCoreFileExtractor::extractMappedFiles() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::vector<std::string>
DarwinCoreFileExtractor::missingModules() const
{
    throw std::runtime_error("Core files are not supported on macOS");
}

std::unique_ptr<AbstractCoreFileExtractor>
AbstractCoreFileExtractor::create(std::shared_ptr<AbstractCoreFileAnalyzer> analyzer)
{
    return std::make_unique<DarwinCoreFileExtractor>(std::move(analyzer));
}

}  // namespace pystack
