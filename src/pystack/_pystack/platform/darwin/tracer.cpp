#include "tracer.h"
#include <vector>

namespace pystack {

ProcessTracer::ProcessTracer(pid_t pid)
{
}
ProcessTracer::~ProcessTracer()
{
}

std::vector<int>
ProcessTracer::getTids() const
{
    return {};
}

void
ProcessTracer::detachFromProcess()
{
}

}  // namespace pystack

// Stub for the free function used in process.cpp (to be exposed via header)
std::vector<int>
getProcessTids(pid_t pid)
{
    return {};
}
