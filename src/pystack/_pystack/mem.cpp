#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <ios>
#include <memory>
#include <sys/uio.h>
#ifdef __linux__
#    include <syscall.h>
#endif
#include <system_error>
#include <unistd.h>
#include <utility>

#ifdef __linux__
#    include "corefile.h"
#endif

#include "logging.h"
#include "mem.h"

namespace pystack {

#ifdef __linux__
using elf_unique_ptr = std::unique_ptr<Elf, std::function<void(Elf*)>>;
#endif

// _process_vm_readv moved to platform/linux/memory.cpp

VirtualMap::VirtualMap(
        uintptr_t start,
        uintptr_t end,
        unsigned long filesize,
        std::string flags,
        unsigned long offset,
        std::string device,
        unsigned long inode,
        std::string pathname)
: d_start(start)
, d_end(end)
, d_filesize(filesize)
, d_flags(std::move(flags))
, d_offset(offset)
, d_device(std::move(device))
, d_inode(inode)
, d_path(std::move(pathname))
{
}

bool
VirtualMap::containsAddr(remote_addr_t addr) const
{
    return d_start <= addr && addr < d_end;
}

uintptr_t
VirtualMap::Start() const
{
    return d_start;
}

uintptr_t
VirtualMap::End() const
{
    return d_end;
}

unsigned long
VirtualMap::FileSize() const
{
    return d_filesize;
}

const std::string&
VirtualMap::Flags() const
{
    return d_flags;
}

unsigned long
VirtualMap::Offset() const
{
    return d_offset;
}

const std::string&
VirtualMap::Device() const
{
    return d_device;
}

unsigned long
VirtualMap::Inode() const
{
    return d_inode;
}

const std::string&
VirtualMap::Path() const
{
    return d_path;
}

size_t
VirtualMap::Size() const
{
    return d_end - d_start;
}

MemoryMapInformation::MemoryMapInformation()
: d_main_map(std::nullopt)
, d_bss(std::nullopt)
, d_heap(std::nullopt)
{
}

const std::optional<VirtualMap>&
MemoryMapInformation::MainMap()
{
    return d_main_map;
}

const std::optional<VirtualMap>&
MemoryMapInformation::Bss()
{
    return d_bss;
}

const std::optional<VirtualMap>&
MemoryMapInformation::Heap()
{
    return d_heap;
}

void
MemoryMapInformation::setMainMap(const VirtualMap& main_map)
{
    d_main_map = main_map;
}

void
MemoryMapInformation::setBss(const VirtualMap& bss)
{
    d_bss = bss;
}

void
MemoryMapInformation::setHeap(const VirtualMap& heap)
{
    d_heap = heap;
}

LRUCache::LRUCache(size_t capacity)
: d_cache_capacity(capacity)
, d_size(0) {};

void
LRUCache::put(uintptr_t key, std::vector<char>&& value)
{
    size_t value_size = value.size();

    if (!can_fit(value_size)) {
        return;
    }

    auto it = d_cache.find(key);

    if (it != d_cache.end()) {
        d_cache_list.erase(it->second.it);
        d_cache.erase(it);
    }

    while (d_size + value_size > d_cache_capacity) {
        d_cache.erase(d_cache_list.back().key);
        d_size -= d_cache_list.back().size;
        d_cache_list.pop_back();
    }

    d_cache_list.push_front(LRUCache::ListNode{key, value_size});
    d_cache[key] = LRUCache::CacheValue{std::move(value), d_cache_list.begin()};
    d_size += value_size;
}

const std::vector<char>&
LRUCache::get(uintptr_t key)
{
    auto it = d_cache.find(key);
    if (it == d_cache.end()) {
        throw std::range_error("There is no such key in the cache");
    } else {
        auto node_it = it->second.it;
        d_cache_list.splice(d_cache_list.begin(), d_cache_list, node_it);
        return it->second.data;
    }
}

bool
LRUCache::exists(uintptr_t key)
{
    return (d_cache.find(key) != d_cache.end());
}

bool
LRUCache::can_fit(size_t size)
{
    return d_cache_capacity >= size;
}

#ifdef __linux__
CorefileRemoteMemoryManager::CorefileRemoteMemoryManager(
        std::shared_ptr<CoreFileAnalyzer> analyzer,
        std::vector<VirtualMap>& vmaps)

: d_analyzer(std::move(analyzer))
, d_vmaps(vmaps)
{
    CoreFileExtractor extractor{d_analyzer};
    d_shared_libs = extractor.ModuleInformation();

    const char* filename = d_analyzer->d_filename.c_str();
    int fd = open(filename, O_RDONLY);

    if (fd == -1) {
        LOG(ERROR) << "Failed to open a file " << filename;
        throw RemoteMemCopyError();
    }

    StatusCode ret = readCorefile(fd, filename);
    int close_ret = close(fd);

    if (close_ret == -1) {
        LOG(ERROR) << "Failed to close a file " << filename;
        throw RemoteMemCopyError();
    }

    if (ret == StatusCode::ERROR) {
        throw RemoteMemCopyError();
    }
}

CorefileRemoteMemoryManager::StatusCode
CorefileRemoteMemoryManager::readCorefile(int fd, const char* filename) noexcept
{
    struct stat fileInfo = {0};

    if (fstat(fd, &fileInfo) == -1) {
        LOG(ERROR) << "Failed to get a file size for a file " << filename;
        return StatusCode::ERROR;
    }

    if (fileInfo.st_size == 0) {
        LOG(ERROR) << "File " << filename << " is empty";
        return StatusCode::ERROR;
    }

    d_corefile_size = fileInfo.st_size;

    void* map = mmap(0, d_corefile_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        LOG(ERROR) << "Failed to mmap a file " << filename;
        return StatusCode::ERROR;
    }

    d_corefile_data = std::unique_ptr<char, std::function<void(char*)>>(
            reinterpret_cast<char*>(map),
            [this](auto addr) {
                if (munmap(addr, d_corefile_size) == -1) {
                    LOG(ERROR) << "Failed to un-mmap a file " << d_analyzer->d_filename.c_str();
                }
            });

    int madvise_result = madvise(d_corefile_data.get(), d_corefile_size, MADV_RANDOM);

    if (madvise_result == -1) {
        LOG(WARNING) << "Madvise for a file " << filename << " failed";
    }

    return StatusCode::SUCCESS;
}

ssize_t
CorefileRemoteMemoryManager::copyMemoryFromProcess(remote_addr_t addr, size_t size, void* destination)
        const
{
    off_t offset_in_file = 0;

    StatusCode ret = getMemoryLocationFromCore(addr, &offset_in_file);

    if (ret == StatusCode::SUCCESS) {
        if (size > d_corefile_size || static_cast<size_t>(offset_in_file) > d_corefile_size - size) {
            throw InvalidRemoteAddress();
        }
        memcpy(destination, d_corefile_data.get() + offset_in_file, size);
        return size;
    }

    // The memory may be in the data segment of some shared library
    const std::string* filename = nullptr;
    ret = getMemoryLocationFromElf(addr, &filename, &offset_in_file);

    if (ret == StatusCode::ERROR) {
        throw InvalidRemoteAddress();
    }

    std::ifstream is(*filename, std::ifstream::binary);
    if (is) {
        is.seekg(offset_in_file);
        is.read((char*)destination, size);
    } else {
        LOG(ERROR) << "Failed to read memory from file " << *filename;
        throw InvalidRemoteAddress();
    }
    return size;
}

CorefileRemoteMemoryManager::StatusCode
CorefileRemoteMemoryManager::getMemoryLocationFromCore(remote_addr_t addr, off_t* offset_in_file) const
{
    auto corefile_it = std::find_if(d_vmaps.cbegin(), d_vmaps.cend(), [&](auto& map) {
        // When considering if the data is in the core file, we need to check if the address is
        // within the chunk of the segment in the core file. map.End() corresponds
        // to the end of the segment in memory when the process was alive but when the core was
        // created not all that data will be in the core, so we need to use map.FileSize()
        // to get the end of the segment in the core file.
        uintptr_t fileEnd = map.Start() + map.FileSize();
        return (map.Start() <= addr && addr < fileEnd) && (map.FileSize() != 0 && map.Offset() != 0);
    });
    if (corefile_it == d_vmaps.cend()) {
        return StatusCode::ERROR;
    }

    off_t base = corefile_it->Offset() - corefile_it->Start();
    *offset_in_file = base + addr;
    return StatusCode::SUCCESS;
}

CorefileRemoteMemoryManager::StatusCode
CorefileRemoteMemoryManager::initLoadSegments(const std::string& filename) const
{
    if (d_elf_load_segments_cache.find(filename) != d_elf_load_segments_cache.end()) {
        return StatusCode::SUCCESS;
    }

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) {
        LOG(ERROR) << "Could not open " << filename << ". Reason: " << strerror(errno);
        return StatusCode::ERROR;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        LOG(ERROR) << "ELF library initialization failed: " << elf_errmsg(-1);
        close(fd);
        return StatusCode::ERROR;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        LOG(ERROR) << "elf_begin() failed: " << elf_errmsg(-1);
        close(fd);
        return StatusCode::ERROR;
    }

    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) != 0) {
        LOG(ERROR) << "elf_getphdrnum() failed: " << elf_errmsg(-1);
        elf_end(elf);
        close(fd);
        return StatusCode::ERROR;
    }

    std::vector<ElfLoadSegment> load_segments;
    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            LOG(ERROR) << "gelf_getphdr() failed: " << elf_errmsg(-1);
            continue;
        }

        if (phdr.p_type == PT_LOAD) {
            load_segments.push_back({phdr.p_vaddr, phdr.p_offset, phdr.p_memsz});
        }
    }

    d_elf_load_segments_cache[filename] = std::move(load_segments);

    elf_end(elf);
    close(fd);
    return StatusCode::SUCCESS;
}

CorefileRemoteMemoryManager::StatusCode
CorefileRemoteMemoryManager::getMemoryLocationFromElf(
        remote_addr_t addr,
        const std::string** filename,
        off_t* offset_in_file) const
{
    auto shared_libs_it = std::find_if(d_shared_libs.cbegin(), d_shared_libs.cend(), [&](auto& map) {
        return map.start <= addr && addr < map.end;
    });

    if (shared_libs_it == d_shared_libs.cend()) {
        return StatusCode::ERROR;
    }

    *filename = &shared_libs_it->filename;

    // Check if we have cached segments for this file
    auto cache_it = d_elf_load_segments_cache.find(**filename);
    if (cache_it == d_elf_load_segments_cache.end()) {
        // Initialize segments if not in cache
        if (initLoadSegments(**filename) != StatusCode::SUCCESS) {
            return StatusCode::ERROR;
        }
        cache_it = d_elf_load_segments_cache.find(**filename);
    }

    // Get the load address of the elf file from its first segment
    remote_addr_t elf_load_addr = cache_it->second[0].vaddr;

    // Now relocate the address to the elf file
    remote_addr_t symbol_vaddr = addr - shared_libs_it->start + elf_load_addr;

    // Find the segment containing this address
    for (const auto& segment : cache_it->second) {
        if (symbol_vaddr >= segment.vaddr && symbol_vaddr < segment.vaddr + segment.size) {
            *offset_in_file = (symbol_vaddr - segment.vaddr) + segment.offset;
            return StatusCode::SUCCESS;
        }
    }

    LOG(ERROR) << "Failed to find the correct segment for address " << std::hex << std::showbase << addr
               << " (with vaddr offset " << symbol_vaddr << ")"
               << " in file " << **filename;

    return StatusCode::ERROR;
}

bool
CorefileRemoteMemoryManager::isAddressValid(remote_addr_t addr, const VirtualMap& map) const
{
    if (addr == (uintptr_t)nullptr) {
        return false;
    }
    return map.Start() <= addr && addr < map.Start() + map.Size();
}
#endif

}  // namespace pystack
