#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

namespace pystack {

struct ModuleInfo
{
    std::string name;
    std::string path;
    uintptr_t load_address;
    uintptr_t end_address;
    std::optional<std::string> build_id;
};

class AbstractAnalyzer
{
  public:
    virtual ~AbstractAnalyzer() = default;

    virtual std::optional<uintptr_t>
    getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const = 0;

    virtual std::vector<ModuleInfo> getModules() const = 0;
    virtual std::optional<ModuleInfo> findModule(const std::string& name) const = 0;

    virtual uintptr_t getModuleLoadPoint(const ModuleInfo& module) const = 0;
};

class AbstractProcessAnalyzer : public AbstractAnalyzer
{
  public:
    ~AbstractProcessAnalyzer() override = default;

    virtual pid_t getPid() const
    {
        return d_pid;
    }

    static std::shared_ptr<AbstractProcessAnalyzer> create(pid_t pid);

  protected:
    explicit AbstractProcessAnalyzer(pid_t pid)
    : d_pid(pid)
    {
    }

    pid_t d_pid;
};

class AbstractCoreFileAnalyzer : public AbstractAnalyzer
{
  public:
    ~AbstractCoreFileAnalyzer() override = default;

    virtual std::string locateLibrary(const std::string& lib) const = 0;
    virtual std::vector<std::string> getMissingModules() const = 0;
    virtual pid_t getPid() const = 0;

    static std::shared_ptr<AbstractCoreFileAnalyzer>
    create(const std::string& corefile,
           std::optional<std::string> executable = std::nullopt,
           std::optional<std::string> lib_search_path = std::nullopt);

  protected:
    explicit AbstractCoreFileAnalyzer(
            std::string corefile,
            std::optional<std::string> executable = std::nullopt,
            std::optional<std::string> lib_search_path = std::nullopt)
    : d_filename(std::move(corefile))
    , d_executable(std::move(executable))
    , d_lib_search_path(std::move(lib_search_path))
    {
    }

    std::string d_filename;
    std::optional<std::string> d_executable;
    std::optional<std::string> d_lib_search_path;
};

}  // namespace pystack
