#include "abstract_tracer.h"
#include <memory>
#include <stdexcept>

#ifdef __linux__
#    include "platform/linux/tracer.h"
#elif defined(__APPLE__)
#    include "platform/darwin/tracer.h"
#endif

namespace pystack {

std::shared_ptr<AbstractProcessTracer>
AbstractProcessTracer::create(pid_t pid)
{
#ifdef __linux__
    return std::make_shared<LinuxProcessTracer>(pid);
#elif defined(__APPLE__)
    return std::make_shared<DarwinProcessTracer>(pid);
#else
    throw std::runtime_error("Pystack remote not supported on this platform");
#endif
}

}  // namespace pystack
