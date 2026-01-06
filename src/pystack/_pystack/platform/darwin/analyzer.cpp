#include "platform/darwin/analyzer.h"

#include <memory>
#include <stdexcept>

namespace pystack {

MachProcessAnalyzer::MachProcessAnalyzer(pid_t pid)
: AbstractProcessAnalyzer(pid)
{
    throw std::runtime_error("Process analyzer not implemented on macOS");
}

std::optional<uintptr_t>
MachProcessAnalyzer::getSymbolAddress(const std::string& /* symbol */, const ModuleInfo& /* module */)
        const
{
    throw std::runtime_error("Process analyzer not implemented on macOS");
}

std::vector<ModuleInfo>
MachProcessAnalyzer::getModules() const
{
    throw std::runtime_error("Process analyzer not implemented on macOS");
}

std::optional<ModuleInfo>
MachProcessAnalyzer::findModule(const std::string& /* name */) const
{
    throw std::runtime_error("Process analyzer not implemented on macOS");
}

uintptr_t
MachProcessAnalyzer::getModuleLoadPoint(const ModuleInfo& /* module */) const
{
    throw std::runtime_error("Process analyzer not implemented on macOS");
}

MachCoreFileAnalyzer::MachCoreFileAnalyzer(
        std::string corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
: AbstractCoreFileAnalyzer(std::move(corefile), std::move(executable), std::move(lib_search_path))
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::optional<uintptr_t>
MachCoreFileAnalyzer::getSymbolAddress(const std::string& /* symbol */, const ModuleInfo& /* module */)
        const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::vector<ModuleInfo>
MachCoreFileAnalyzer::getModules() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::optional<ModuleInfo>
MachCoreFileAnalyzer::findModule(const std::string& /* name */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

uintptr_t
MachCoreFileAnalyzer::getModuleLoadPoint(const ModuleInfo& /* module */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::string
MachCoreFileAnalyzer::locateLibrary(const std::string& /* lib */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::vector<std::string>
MachCoreFileAnalyzer::getMissingModules() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

pid_t
MachCoreFileAnalyzer::getPid() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::shared_ptr<AbstractProcessAnalyzer>
AbstractProcessAnalyzer::create(pid_t pid)
{
    return std::make_shared<MachProcessAnalyzer>(pid);
}

std::shared_ptr<AbstractCoreFileAnalyzer>
AbstractCoreFileAnalyzer::create(
        const std::string& corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
{
    return std::make_shared<MachCoreFileAnalyzer>(
            corefile,
            std::move(executable),
            std::move(lib_search_path));
}

}  // namespace pystack
