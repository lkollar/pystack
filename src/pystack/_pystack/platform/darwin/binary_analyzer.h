#pragma once

#include "platform/binary_analyzer.h"

#include <string>

namespace pystack {

class MachOBinaryAnalyzer : public AbstractBinaryAnalyzer
{
  public:
    // Constructors
    explicit MachOBinaryAnalyzer(const std::string& path);

    // Methods - all throw "not implemented" for now
    std::optional<SectionInfo> findSection(const std::string& name) const override;
    std::string getBuildId() const override;

  private:
    std::string d_path;
};

}  // namespace pystack
