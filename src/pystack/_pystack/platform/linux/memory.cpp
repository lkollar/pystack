#include "platform/linux/memory.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <system_error>
#include <unistd.h>

#include <sys/syscall.h>
#include <sys/uio.h>

#include "logging.h"
#include "mem.h"

namespace pystack {

namespace {

static const std::string PERM_MESSAGE = "Operation not permitted";

static ssize_t
process_vm_readv_wrapper(
        pid_t pid,
        const struct iovec* lvec,
        unsigned long liovcnt,
        const struct iovec* rvec,
        unsigned long riovcnt,
        unsigned long flags)
{
#ifndef SYS_process_vm_readv
    errno = ENOSYS;
    return -1;
#else
    return syscall(SYS_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
#endif
}

}  // namespace

LinuxProcessMemoryManager::LinuxProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
: UnixRemoteMemoryManager(vmaps)
, d_pid(pid)
{
}

LinuxProcessMemoryManager::LinuxProcessMemoryManager(pid_t pid)
: UnixRemoteMemoryManager()
, d_pid(pid)
{
}

ssize_t
LinuxProcessMemoryManager::readChunk(remote_addr_t addr, size_t len, char* dst) const
{
    if (d_memfile || getenv("_PYSTACK_NO_PROCESS_VM_READV") != nullptr) {
        return readChunkThroughMemFile(addr, len, dst);
    }
    return readChunkDirect(addr, len, dst);
}

ssize_t
LinuxProcessMemoryManager::readChunkDirect(remote_addr_t addr, size_t len, char* dst) const
{
    struct iovec local[1];
    struct iovec remote[1];
    ssize_t result = 0;
    ssize_t read = 0;

    do {
        local[0].iov_base = dst + result;
        local[0].iov_len = len - result;
        remote[0].iov_base = reinterpret_cast<uint8_t*>(addr) + result;
        remote[0].iov_len = len - result;

        read = process_vm_readv_wrapper(d_pid, local, 1, remote, 1, 0);
        if (read < 0) {
            if (errno == EFAULT) {
                throw InvalidRemoteAddress();
            } else if (errno == EPERM) {
                throw RemoteMemPermissionError();
            } else if (errno == ENOSYS) {
                LOG(DEBUG) << "process_vm_readv not compiled in kernel, falling back to /proc/PID/mem";
                return readChunkThroughMemFile(addr, len, dst);
            }
            throw std::system_error(errno, std::generic_category());
        }

        result += read;
    } while ((size_t)read != local[0].iov_len);

    return result;
}

ssize_t
LinuxProcessMemoryManager::readChunkThroughMemFile(remote_addr_t addr, size_t len, char* dst) const
{
    if (!d_memfile) {
        std::string filepath = "/proc/" + std::to_string(d_pid) + "/mem";
        d_memfile = file_unique_ptr(fopen(filepath.c_str(), "r"), fclose);
        if (!d_memfile) {
            if (errno == EPERM || errno == EACCES) {
                LOG(ERROR) << "Permission denied opening file " << filepath;
                throw RemoteMemPermissionError();
            }
            LOG(ERROR) << "Failed to open file " << filepath << ": " << std::strerror(errno);
            throw std::runtime_error("Failed to open " + filepath);
        }
    }
    fseeko(d_memfile.get(), addr, SEEK_SET);
    if (static_cast<off_t>(addr) != ftello(d_memfile.get())
        || len != fread(dst, 1, len, d_memfile.get()))
    {
        throw InvalidRemoteAddress();
    }
    return static_cast<ssize_t>(len);
}

std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid)
{
    return std::make_unique<LinuxProcessMemoryManager>(pid);
}

std::unique_ptr<AbstractRemoteMemoryManager>
createProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
{
    return std::make_unique<LinuxProcessMemoryManager>(pid, vmaps);
}

}  // namespace pystack
