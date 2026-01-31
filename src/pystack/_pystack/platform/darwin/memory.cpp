#include "platform/darwin/memory.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <mach/mach_error.h>
#include <mach/mach_vm.h>

#include "logging.h"
#include "mem.h"

namespace pystack {

namespace {

static const std::string PERM_MESSAGE = "Operation not permitted";

}  // namespace

DarwinProcessMemoryManager::DarwinProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
: UnixRemoteMemoryManager(vmaps)
, d_task(MACH_PORT_NULL)
{
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &d_task);
    if (kr != KERN_SUCCESS) {
        throw std::runtime_error("Failed to obtain task port: " + std::string(mach_error_string(kr)));
    }
}

DarwinProcessMemoryManager::DarwinProcessMemoryManager(pid_t pid)
: UnixRemoteMemoryManager()
, d_task(MACH_PORT_NULL)
{
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &d_task);
    if (kr != KERN_SUCCESS) {
        throw std::runtime_error("Failed to obtain task port: " + std::string(mach_error_string(kr)));
    }
}

ssize_t
DarwinProcessMemoryManager::readChunk(remote_addr_t addr, size_t len, char* dst) const
{
    mach_vm_size_t bytes_read = 0;
    kern_return_t kr = mach_vm_read_overwrite(
            d_task,
            static_cast<mach_vm_address_t>(addr),
            static_cast<mach_vm_size_t>(len),
            reinterpret_cast<mach_vm_address_t>(dst),
            &bytes_read);
    if (kr == KERN_SUCCESS) {
        return static_cast<ssize_t>(bytes_read);
    }
    if (kr == KERN_INVALID_ADDRESS) {
        throw InvalidRemoteAddress();
    }
    if (kr == KERN_PROTECTION_FAILURE || kr == KERN_NO_ACCESS || kr == KERN_INVALID_TASK) {
        throw RemoteMemPermissionError();
    }
    throw std::runtime_error("Failed to read memory: " + std::string(mach_error_string(kr)));
}

std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid)
{
    return std::make_unique<DarwinProcessMemoryManager>(pid);
}

std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
{
    return std::make_unique<DarwinProcessMemoryManager>(pid, vmaps);
}

}  // namespace pystack
