#pragma once

#include <analyzer.h>

namespace pystack {

class MachProcessAnalyzer : public AbstractProcessAnalyzer
{
  public:
    explicit MachProcessAnalyzer(pid_t pid);
    ~MachProcessAnalyzer() override = default;

    std::optional<uintptr_t>
    getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const override;
    std::vector<ModuleInfo> getModules() const override;
    std::optional<ModuleInfo> findModule(const std::string& name) const override;
    uintptr_t getModuleLoadPoint(const ModuleInfo& module) const override;
};

class MachCoreFileAnalyzer : public AbstractCoreFileAnalyzer
{
  public:
    explicit MachCoreFileAnalyzer(
            std::string corefile,
            std::optional<std::string> executable = std::nullopt,
            std::optional<std::string> lib_search_path = std::nullopt);
    ~MachCoreFileAnalyzer() override = default;

    std::optional<uintptr_t>
    getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const override;
    std::vector<ModuleInfo> getModules() const override;
    std::optional<ModuleInfo> findModule(const std::string& name) const override;
    uintptr_t getModuleLoadPoint(const ModuleInfo& module) const override;

    std::string locateLibrary(const std::string& lib) const override;
    std::vector<std::string> getMissingModules() const override;
    pid_t getPid() const override;
};

}  // namespace pystack
