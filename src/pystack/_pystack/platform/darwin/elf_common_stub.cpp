#ifdef __APPLE__
#    include "platform/darwin/elf_common_stub.h"

namespace pystack {

ProcessAnalyzer::ProcessAnalyzer(int /* pid */)
{
    throw std::runtime_error("ProcessAnalyzer not implemented on macOS");
}

const dwfl_unique_ptr&
ProcessAnalyzer::getDwfl() const
{
    throw std::runtime_error("ProcessAnalyzer not implemented on macOS");
}

CoreFileAnalyzer::CoreFileAnalyzer(
        std::string /* corefile */,
        std::optional<std::string> /* executable */,
        const std::optional<std::string>& /* lib_search_path */)
{
    throw std::runtime_error("CoreFileAnalyzer not implemented on macOS");
}

CoreFileAnalyzer::~CoreFileAnalyzer() = default;

const dwfl_unique_ptr&
CoreFileAnalyzer::getDwfl() const
{
    throw std::runtime_error("CoreFileAnalyzer not implemented on macOS");
}

std::string
CoreFileAnalyzer::locateLibrary(const std::string& /* lib */) const
{
    throw std::runtime_error("CoreFileAnalyzer not implemented on macOS");
}

}  // namespace pystack

#endif  // __APPLE__
