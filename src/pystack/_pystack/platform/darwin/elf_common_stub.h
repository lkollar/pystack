// Stub declarations for Darwin to satisfy type requirements.
// These will be replaced with real implementations in the future.

#pragma once

#ifdef __APPLE__

#    include <functional>
#    include <memory>
#    include <optional>
#    include <stdexcept>
#    include <string>
#    include <vector>

namespace pystack {

// Stub dwfl_unique_ptr type (void pointer since we don't have DWFL on Darwin)
using dwfl_unique_ptr = std::unique_ptr<void, std::function<void(void*)>>;

// Abstract base class for analyzers (matches Linux version)
class Analyzer
{
  public:
    virtual ~Analyzer() = default;
    virtual const dwfl_unique_ptr& getDwfl() const = 0;
};

class ProcessAnalyzer : public Analyzer
{
  public:
    explicit ProcessAnalyzer(int pid);
    const dwfl_unique_ptr& getDwfl() const override;

  private:
    dwfl_unique_ptr d_dwfl;
};

class CoreFileAnalyzer : public Analyzer
{
  public:
    explicit CoreFileAnalyzer(
            std::string corefile,
            std::optional<std::string> executable = std::nullopt,
            const std::optional<std::string>& lib_search_path = std::nullopt);

    ~CoreFileAnalyzer() override;

    const dwfl_unique_ptr& getDwfl() const override;
    std::string locateLibrary(const std::string& lib) const;

    // Public data members that may be referenced
    dwfl_unique_ptr d_dwfl;
    char* d_debuginfo_path;
    std::string d_filename;
    std::optional<std::string> d_executable;
    std::optional<std::string> d_lib_search_path;
    int d_fd;
    int d_pid;
    std::vector<std::string> d_missing_modules;
};

}  // namespace pystack

#endif  // __APPLE__
