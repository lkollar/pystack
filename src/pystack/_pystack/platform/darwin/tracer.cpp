#include "tracer.h"

#include <stdexcept>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/vm_map.h>

#include "logging.h"

namespace pystack {

DarwinProcessTracer::DarwinProcessTracer(pid_t pid)
: d_task(MACH_PORT_NULL)
{
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &d_task);
    if (kr != KERN_SUCCESS) {
        throw std::runtime_error("Failed to obtain task port: " + std::string(mach_error_string(kr)));
    }

    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t thread_count = 0;
    kr = task_threads(d_task, &threads, &thread_count);
    if (kr != KERN_SUCCESS) {
        throw std::runtime_error("Failed to list threads: " + std::string(mach_error_string(kr)));
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        d_tids.insert(static_cast<int>(threads[i]));
    }

    if (threads) {
        vm_deallocate(
                mach_task_self(),
                reinterpret_cast<vm_address_t>(threads),
                static_cast<vm_size_t>(thread_count * sizeof(thread_act_t)));
    }

    LOG(INFO) << "Attached to task with " << d_tids.size() << " threads";
}

void
DarwinProcessTracer::detachFromProcess()
{
    if (d_task == MACH_PORT_NULL) {
        return;
    }

    for (auto tid : d_tids) {
        mach_port_deallocate(mach_task_self(), static_cast<mach_port_t>(tid));
    }
    d_tids.clear();
    mach_port_deallocate(mach_task_self(), d_task);
    d_task = MACH_PORT_NULL;
}

DarwinProcessTracer::~DarwinProcessTracer()
{
    try {
        detachFromProcess();
    } catch (...) {
        // Avoid throwing in destructor.
    }
}

std::vector<int>
DarwinProcessTracer::getTids() const
{
    return {d_tids.begin(), d_tids.end()};
}

}  // namespace pystack
