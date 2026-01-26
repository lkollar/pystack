#include "process_info.h"

#include <cerrno>
#include <csignal>
#include <stdexcept>
#include <string>

#include "logging.h"

#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>

namespace pystack {

namespace {

static const std::string PERM_MESSAGE = "Operation not permitted";

std::string
formatMachError(const std::string& prefix, kern_return_t kr)
{
    return prefix + ": " + std::string(mach_error_string(kr));
}

std::string
formatPermissions(vm_prot_t prot, unsigned char share_mode)
{
    std::string perms;
    perms += (prot & VM_PROT_READ) ? "r" : "-";
    perms += (prot & VM_PROT_WRITE) ? "w" : "-";
    perms += (prot & VM_PROT_EXECUTE) ? "x" : "-";

    bool shared = share_mode == SM_SHARED || share_mode == SM_TRUESHARED;
    perms += shared ? "s" : "p";
    return perms;
}

}  // namespace

std::string
DarwinProcessInfo::getExecutablePath(pid_t pid) const
{
    char buf[PATH_MAX];
    int len = proc_pidpath(pid, buf, sizeof(buf));
    if (len <= 0) {
        throw std::ios_base::failure("Failed to read executable path");
    }
    return std::string(buf);
}

std::string
DarwinProcessInfo::getThreadName(pid_t pid, int tid) const
{
    proc_threadinfo info{};
    int ret = proc_pidinfo(pid, PROC_PIDTHREADINFO, static_cast<uint64_t>(tid), &info, sizeof(info));
    if (ret == sizeof(info)) {
        return info.pth_name[0] ? std::string(info.pth_name) : "";
    }
    if (ret <= 0) {
        throw std::ios_base::failure("Failed to read thread name");
    }
    return "";
}

bool
DarwinProcessInfo::processExists(pid_t pid) const
{
    if (pid <= 0) {
        return false;
    }
    if (kill(pid, 0) == 0) {
        return true;
    }
    return errno == EPERM;
}

std::vector<VirtualMap>
DarwinProcessInfo::getMemoryMaps(pid_t pid) const
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        if (kr == KERN_PROTECTION_FAILURE || kr == KERN_INVALID_TASK) {
            throw std::runtime_error(PERM_MESSAGE);
        }
        throw std::runtime_error(formatMachError("Failed to obtain task port", kr));
    }

    LOG(DEBUG) << "Reading memory maps for pid " << pid;

    std::vector<VirtualMap> maps;
    mach_vm_address_t address = 0;
    uint32_t depth = 0;

    while (true) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kr = mach_vm_region_recurse(
                task,
                &address,
                &size,
                &depth,
                reinterpret_cast<vm_region_recurse_info_t>(&info),
                &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        }
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), task);
            throw std::runtime_error(formatMachError("Failed to read memory maps", kr));
        }
        if (info.is_submap) {
            depth++;
            continue;
        }

        std::string perms = formatPermissions(info.protection, info.share_mode);
        std::string path;
        char pathbuf[PATH_MAX];
        int path_len = proc_regionfilename(pid, address, pathbuf, sizeof(pathbuf));
        if (path_len > 0) {
            pathbuf[sizeof(pathbuf) - 1] = '\0';
            path = pathbuf;
        }

        maps.emplace_back(
                static_cast<uintptr_t>(address),
                static_cast<uintptr_t>(address + size),
                static_cast<unsigned long>(size),
                perms,
                static_cast<unsigned long>(info.offset),
                "",
                0,
                path);

        address += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return maps;
}

std::unique_ptr<AbstractProcessInfo>
AbstractProcessInfo::create()
{
    return std::make_unique<DarwinProcessInfo>();
}

}  // namespace pystack
