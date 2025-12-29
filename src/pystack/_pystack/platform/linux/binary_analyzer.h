#pragma once

#include "elf_common.h"
#include "platform/binary_analyzer.h"

#include <string>

namespace pystack {

class ElfBinaryAnalyzer : public AbstractBinaryAnalyzer
{
  public:
    // Constructors
    explicit ElfBinaryAnalyzer(const std::string& path);
    ElfBinaryAnalyzer(const std::string& path, const dwfl_unique_ptr& dwfl);

    // Methods from AbstractBinaryAnalyzer
    std::optional<SectionInfo> findSection(const std::string& name) const override;
    std::string getBuildId() const override;

    // Linux-specific: get load point using DWFL handle
    uintptr_t getLoadPoint() const;

  private:
    std::string d_path;
    const dwfl_unique_ptr* d_dwfl;
};

}  // namespace pystack
