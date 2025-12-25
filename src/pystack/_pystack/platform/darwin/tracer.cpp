#include "tracer.h"

#include <stdexcept>

namespace pystack {

DarwinProcessTracer::DarwinProcessTracer(pid_t pid)
{
    (void)pid;
    throw std::runtime_error("Darwin DarwinProcessTracer not implemented");
}

void
DarwinProcessTracer::detachFromProcess()
{
    throw std::runtime_error("Darwin DarwinProcessTracer not implemented");
}

DarwinProcessTracer::~DarwinProcessTracer()
{
}

std::vector<int>
DarwinProcessTracer::getTids() const
{
    throw std::runtime_error("Darwin DarwinProcessTracer not implemented");
}

}  // namespace pystack
