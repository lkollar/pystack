#include "memory.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <ios>
#include <memory>
#include <sys/uio.h>
#include <syscall.h>
#include <system_error>
#include <unistd.h>
#include <utility>

#include "logging.h"

namespace pystack {

static ssize_t
_process_vm_readv(
        pid_t pid,
        const struct iovec* lvec,
        unsigned long liovcnt,
        const struct iovec* rvec,
        unsigned long riovcnt,
        unsigned long flags)
{
    return syscall(SYS_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

static const std::string PERM_MESSAGE = "Operation not permitted";
static const size_t CACHE_CAPACITY = 5e+7;  // 50MB

ProcessMemoryManager::ProcessMemoryManager(pid_t pid, const std::vector<VirtualMap>& vmaps)
: d_pid(pid)
, d_vmaps(vmaps)
, d_lru_cache(CACHE_CAPACITY)
{
}

ProcessMemoryManager::ProcessMemoryManager(pid_t pid)
: d_pid(pid)
, d_lru_cache(CACHE_CAPACITY)
{
}

ssize_t
ProcessMemoryManager::readChunk(remote_addr_t addr, size_t len, char* dst) const
{
    if (d_memfile || getenv("_PYSTACK_NO_PROCESS_VM_READV") != nullptr) {
        return readChunkThroughMemFile(addr, len, dst);
    } else {
        return readChunkDirect(addr, len, dst);
    }
}

ssize_t
ProcessMemoryManager::readChunkDirect(remote_addr_t addr, size_t len, char* dst) const
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

        read = _process_vm_readv(d_pid, local, 1, remote, 1, 0);
        if (read < 0) {
            if (errno == EFAULT) {
                throw InvalidRemoteAddress();
            } else if (errno == EPERM) {
                throw std::runtime_error(PERM_MESSAGE);
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
ProcessMemoryManager::readChunkThroughMemFile(remote_addr_t addr, size_t len, char* dst) const
{
    if (!d_memfile) {
        std::string filepath = "/proc/" + std::to_string(d_pid) + "/mem";
        d_memfile = file_unique_ptr(fopen(filepath.c_str(), "r"), fclose);
        if (!d_memfile) {
            if (errno == EPERM || errno == EACCES) {
                LOG(ERROR) << "Permission denied opening file " << filepath;
                throw std::runtime_error(PERM_MESSAGE);
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

ssize_t
ProcessMemoryManager::copyMemoryFromProcess(remote_addr_t addr, size_t len, void* dst) const
{
    auto vmap = std::find_if(d_vmaps.begin(), d_vmaps.end(), [&](const auto& vmap) {
        return vmap.containsAddr(addr) && vmap.containsAddr(addr + len - 1);
    });

    if (vmap == d_vmaps.end() || !d_lru_cache.can_fit(vmap->Size())) {
        return readChunk(addr, len, reinterpret_cast<char*>(dst));
    }

    uintptr_t key = vmap->Start();
    size_t chunk_size = vmap->Size();
    remote_addr_t vmap_start_addr = vmap->Start();
    size_t offset_addr = addr - vmap_start_addr;

    if (!d_lru_cache.exists(key)) {
        std::vector<char> buf(chunk_size);
        readChunk(vmap_start_addr, chunk_size, buf.data());
        d_lru_cache.put(key, std::move(buf));
    }

    std::memcpy(dst, d_lru_cache.get(key).data() + offset_addr, len);

    return len;
}

bool
ProcessMemoryManager::isAddressValid(remote_addr_t addr, const VirtualMap& map) const
{
    if (addr == (uintptr_t)nullptr) {
        return false;
    }
    return map.Start() <= addr && addr < map.End();
}

}  // namespace pystack
