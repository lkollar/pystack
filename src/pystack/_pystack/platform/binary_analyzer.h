#pragma once

#include <memory>
#include <optional>
#include <string>

namespace pystack {

struct SectionInfo
{
    std::string name;
    std::string flags;
    uintptr_t addr;
    uintptr_t corrected_addr;
    off_t offset;
    size_t size;
};

class AbstractBinaryAnalyzer
{
  public:
    virtual ~AbstractBinaryAnalyzer() = default;

    // Find section by name (e.g., ".bss", ".PyRuntime", "__DATA")
    virtual std::optional<SectionInfo> findSection(const std::string& name) const = 0;

    // Get Build ID (ELF) / UUID (Mach-O)
    virtual std::string getBuildId() const = 0;

    // Factory method - returns platform-appropriate analyzer
    static std::unique_ptr<AbstractBinaryAnalyzer> create(const std::string& path);
};

}  // namespace pystack
