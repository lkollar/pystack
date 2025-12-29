#include "platform/darwin/binary_analyzer.h"
#include "logging.h"

#include <stdexcept>

namespace pystack {

MachOBinaryAnalyzer::MachOBinaryAnalyzer(const std::string& path)
: d_path(path)
{
}

std::optional<SectionInfo>
MachOBinaryAnalyzer::findSection(const std::string& name) const
{
    throw std::runtime_error("MachOBinaryAnalyzer::findSection not implemented");
}

std::string
MachOBinaryAnalyzer::getBuildId() const
{
    throw std::runtime_error("MachOBinaryAnalyzer::getBuildId not implemented");
}

std::unique_ptr<AbstractBinaryAnalyzer>
AbstractBinaryAnalyzer::create(const std::string& path)
{
    return std::make_unique<MachOBinaryAnalyzer>(path);
}

}  // namespace pystack
