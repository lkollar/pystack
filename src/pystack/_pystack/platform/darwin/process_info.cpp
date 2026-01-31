#include "process_info.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string>

#include "logging.h"

#include <libproc.h>
#include <mach/kern_return.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
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
    LOG(DEBUG) << "task_for_pid(" << pid << ") -> " << kr << " (" << mach_error_string(kr) << ")";
    if (kr != KERN_SUCCESS) {
        if (kr == KERN_PROTECTION_FAILURE || kr == KERN_INVALID_TASK) {
            throw std::runtime_error(PERM_MESSAGE);
        }
        throw std::runtime_error(formatMachError("Failed to obtain task port", kr));
    }

    task_basic_info_data_t task_info_data{};
    mach_msg_type_number_t task_info_count = TASK_BASIC_INFO_COUNT;
    kern_return_t task_info_kr = task_info(
            task,
            TASK_BASIC_INFO,
            reinterpret_cast<task_info_t>(&task_info_data),
            &task_info_count);
    LOG(DEBUG) << "task_info(TASK_BASIC_INFO) -> " << task_info_kr << " ("
               << mach_error_string(task_info_kr) << ")";

    LOG(DEBUG) << "Reading memory maps for pid " << pid;

    int kill_result = kill(pid, 0);
    int kill_errno = errno;
    LOG(DEBUG) << "kill(" << pid << ", 0) -> " << kill_result << " (errno=" << kill_errno << ": "
               << std::strerror(kill_errno) << ")";

    mach_port_type_t port_type = 0;
    kern_return_t port_type_kr = mach_port_type(mach_task_self(), task, &port_type);
    LOG(DEBUG) << "mach_port_type(task) -> " << port_type_kr << " (" << mach_error_string(port_type_kr)
               << "), type=0x" << std::hex << port_type << std::dec;

    std::vector<VirtualMap> maps;
    mach_vm_address_t address = 0;
    uint32_t depth = 0;

    auto refill_task = [&task, pid]() {
        if (task != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task);
        }
        task = MACH_PORT_NULL;
        kern_return_t refill_kr = task_for_pid(mach_task_self(), pid, &task);
        LOG(DEBUG) << "retry task_for_pid(" << pid << ") -> " << refill_kr << " ("
                   << mach_error_string(refill_kr) << ")";
        return refill_kr == KERN_SUCCESS;
    };

    auto add_fallback_region = [&](kern_return_t error_code) {
        if (error_code != MACH_SEND_INVALID_DEST) {
            return false;
        }

        mach_vm_address_t fallback_address = address;
        mach_vm_size_t fallback_size = 0;
        vm_region_basic_info_data_64_t basic_info{};
        mach_msg_type_number_t basic_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;
        kern_return_t fallback_kr = mach_vm_region(
                task,
                &fallback_address,
                &fallback_size,
                VM_REGION_BASIC_INFO_64,
                reinterpret_cast<vm_region_info_t>(&basic_info),
                &basic_count,
                &object_name);
        LOG(DEBUG) << "mach_vm_region fallback -> " << fallback_kr << " ("
                   << mach_error_string(fallback_kr) << ")";
        if (fallback_kr != KERN_SUCCESS) {
            return false;
        }

        std::string perms = formatPermissions(basic_info.protection, basic_info.shared);
        std::string path;
        char pathbuf[PATH_MAX];
        int path_len = proc_regionfilename(pid, fallback_address, pathbuf, sizeof(pathbuf));
        if (path_len > 0) {
            pathbuf[sizeof(pathbuf) - 1] = '\0';
            path = pathbuf;
        }
        maps.emplace_back(
                static_cast<uintptr_t>(fallback_address),
                static_cast<uintptr_t>(fallback_address + fallback_size),
                static_cast<unsigned long>(fallback_size),
                perms,
                static_cast<unsigned long>(basic_info.offset),
                "",
                0,
                path);
        address = fallback_address + fallback_size;
        return true;
    };

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

        // Occasionally, mach_vm_region_recurse may return
        // MACH_SEND_INVALID_DEST when the port becomes invalid mid-scan.
        // Re-acquire the task port and retry.
        if (kr == MACH_SEND_INVALID_DEST) {
            LOG(DEBUG) << "mach_vm_region_recurse got invalid destination, retrying";
            if (refill_task()) {
                kr = mach_vm_region_recurse(
                        task,
                        &address,
                        &size,
                        &depth,
                        reinterpret_cast<vm_region_recurse_info_t>(&info),
                        &count);
            }
        }

        if (kr != KERN_SUCCESS) {
            LOG(DEBUG) << "mach_vm_region_recurse failed: " << kr << " (" << mach_error_string(kr)
                       << ")";
            if (add_fallback_region(kr)) {
                continue;
            }
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
