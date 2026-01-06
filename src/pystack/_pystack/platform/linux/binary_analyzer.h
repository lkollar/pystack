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

    // Methods from AbstractBinaryAnalyzer
    std::optional<SectionInfo> findSection(const std::string& name) const override;
    std::string getBuildId() const override;

  private:
    std::string d_path;
};

}  // namespace pystack
