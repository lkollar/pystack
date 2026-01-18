#pragma once

#include "elf_common.h"
#include <analyzer.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace pystack {

class DwflProcessAnalyzer : public AbstractProcessAnalyzer
{
  public:
    explicit DwflProcessAnalyzer(pid_t pid);
    ~DwflProcessAnalyzer() override = default;

    std::optional<uintptr_t>
    getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const override;
    std::vector<ModuleInfo> getModules() const override;
    std::optional<ModuleInfo> findModule(const std::string& name) const override;
    uintptr_t getModuleLoadPoint(const ModuleInfo& module) const override;

    const dwfl_unique_ptr& getDwfl() const
    {
        return d_dwfl;
    }

  private:
    dwfl_unique_ptr d_dwfl;
    char* d_debuginfo_path;
    Dwfl_Callbacks d_callbacks;
};

class DwflCoreFileAnalyzer : public AbstractCoreFileAnalyzer
{
  public:
    explicit DwflCoreFileAnalyzer(
            std::string corefile,
            std::optional<std::string> executable = std::nullopt,
            std::optional<std::string> lib_search_path = std::nullopt);
    ~DwflCoreFileAnalyzer() override;

    std::optional<uintptr_t>
    getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const override;
    std::vector<ModuleInfo> getModules() const override;
    std::optional<ModuleInfo> findModule(const std::string& name) const override;
    uintptr_t getModuleLoadPoint(const ModuleInfo& module) const override;

    std::string locateLibrary(const std::string& lib) const override;
    std::vector<std::string> getMissingModules() const override;
    pid_t getPid() const override;

    const dwfl_unique_ptr& getDwfl() const
    {
        return d_dwfl;
    }

    const elf_unique_ptr& getElf() const
    {
        return d_elf;
    }

    const std::string& getFilename() const
    {
        return d_filename;
    }

  private:
    void removeModuleIf(std::function<bool(Dwfl_Module*)> predicate) const;
    void resolveLibraries();

    dwfl_unique_ptr d_dwfl;
    char* d_debuginfo_path;
    Dwfl_Callbacks d_callbacks;
    int d_fd;
    int d_pid;
    elf_unique_ptr d_elf;
    std::vector<std::string> d_missing_modules{};
};

}  // namespace pystack
