#include "platform/darwin/analyzer.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "logging.h"
#include "platform/process_info.h"

namespace pystack {

namespace {

struct MachOHeaderInfo
{
    uint64_t file_offset;
    bool is_64bit;
};

struct MachOSymtab
{
    uint64_t symoff;
    uint64_t nsyms;
    uint64_t stroff;
    uint64_t strsize;
};

bool
readAt(std::ifstream& file, uint64_t offset, void* out, size_t size)
{
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!file.good()) {
        return false;
    }
    file.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));
    return file.good();
}

cpu_type_t
preferredCpuType()
{
#if defined(__x86_64__)
    return CPU_TYPE_X86_64;
#elif defined(__aarch64__) || defined(__arm64__)
    return CPU_TYPE_ARM64;
#else
    return CPU_TYPE_ANY;
#endif
}

std::optional<MachOHeaderInfo>
findMachOHeader(std::ifstream& file)
{
    uint32_t magic = 0;
    if (!readAt(file, 0, &magic, sizeof(magic))) {
        return std::nullopt;
    }

    auto is64bitAtOffset = [&](uint64_t offset) -> std::optional<bool> {
        uint32_t slice_magic = 0;
        if (!readAt(file, offset, &slice_magic, sizeof(slice_magic))) {
            return std::nullopt;
        }
        if (slice_magic == MH_MAGIC_64 || slice_magic == MH_CIGAM_64) {
            return true;
        }
        if (slice_magic == MH_MAGIC || slice_magic == MH_CIGAM) {
            return false;
        }
        return std::nullopt;
    };

    if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        bool swapped = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        auto swap32 = [swapped](uint32_t value) { return swapped ? __builtin_bswap32(value) : value; };
        auto swap64 = [swapped](uint64_t value) { return swapped ? __builtin_bswap64(value) : value; };
        bool is_fat64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        struct fat_header fh;
        if (!readAt(file, 0, &fh, sizeof(fh))) {
            return std::nullopt;
        }
        uint32_t nfat = swap32(fh.nfat_arch);
        cpu_type_t desired = preferredCpuType();
        std::optional<MachOHeaderInfo> best;

        uint64_t arch_offset = sizeof(fat_header);
        for (uint32_t i = 0; i < nfat; ++i) {
            cpu_type_t cputype = CPU_TYPE_ANY;
            uint64_t offset = 0;
            if (is_fat64) {
                struct fat_arch_64 arch64;
                if (!readAt(file, arch_offset, &arch64, sizeof(arch64))) {
                    return std::nullopt;
                }
                cputype = static_cast<cpu_type_t>(swap32(arch64.cputype));
                offset = swap64(arch64.offset);
                arch_offset += sizeof(arch64);
            } else {
                struct fat_arch arch;
                if (!readAt(file, arch_offset, &arch, sizeof(arch))) {
                    return std::nullopt;
                }
                cputype = static_cast<cpu_type_t>(swap32(arch.cputype));
                offset = swap32(arch.offset);
                arch_offset += sizeof(arch);
            }

            auto is_64bit = is64bitAtOffset(offset);
            if (!is_64bit) {
                continue;
            }

            MachOHeaderInfo candidate{offset, *is_64bit};
            if (desired != CPU_TYPE_ANY && cputype == desired) {
                return candidate;
            }
            if (!best) {
                best = candidate;
            }
        }
        return best;
    }

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        return MachOHeaderInfo{0, true};
    }
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        return MachOHeaderInfo{0, false};
    }
    return std::nullopt;
}

std::optional<std::pair<uint64_t, MachOSymtab>>
findMachOTextAndSymtab(std::ifstream& file, const MachOHeaderInfo& header)
{
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    uint64_t header_offset = header.file_offset;

    if (header.is_64bit) {
        mach_header_64 mh;
        if (!readAt(file, header_offset, &mh, sizeof(mh))) {
            return std::nullopt;
        }
        ncmds = mh.ncmds;
        sizeofcmds = mh.sizeofcmds;
        header_offset += sizeof(mh);
    } else {
        mach_header mh;
        if (!readAt(file, header_offset, &mh, sizeof(mh))) {
            return std::nullopt;
        }
        ncmds = mh.ncmds;
        sizeofcmds = mh.sizeofcmds;
        header_offset += sizeof(mh);
    }

    uint64_t text_vmaddr = 0;
    MachOSymtab symtab{};
    bool found_symtab = false;

    uint64_t cmd_offset = header_offset;
    for (uint32_t i = 0; i < ncmds; ++i) {
        load_command lc;
        if (!readAt(file, cmd_offset, &lc, sizeof(lc))) {
            return std::nullopt;
        }

        if (lc.cmd == LC_SEGMENT_64 && header.is_64bit) {
            segment_command_64 seg;
            if (!readAt(file, cmd_offset, &seg, sizeof(seg))) {
                return std::nullopt;
            }
            if (strncmp(seg.segname, "__TEXT", sizeof(seg.segname)) == 0) {
                text_vmaddr = seg.vmaddr;
            }
        } else if (lc.cmd == LC_SEGMENT && !header.is_64bit) {
            segment_command seg;
            if (!readAt(file, cmd_offset, &seg, sizeof(seg))) {
                return std::nullopt;
            }
            if (strncmp(seg.segname, "__TEXT", sizeof(seg.segname)) == 0) {
                text_vmaddr = seg.vmaddr;
            }
        } else if (lc.cmd == LC_SYMTAB) {
            symtab_command sc;
            if (!readAt(file, cmd_offset, &sc, sizeof(sc))) {
                return std::nullopt;
            }
            symtab.symoff = sc.symoff;
            symtab.nsyms = sc.nsyms;
            symtab.stroff = sc.stroff;
            symtab.strsize = sc.strsize;
            found_symtab = true;
        }

        if (lc.cmdsize == 0) {
            break;
        }
        cmd_offset += lc.cmdsize;
        if (cmd_offset > header_offset + sizeofcmds) {
            break;
        }
    }

    if (!found_symtab) {
        return std::nullopt;
    }
    return std::make_pair(text_vmaddr, symtab);
}

std::vector<std::string>
buildSymbolCandidates(const std::string& symbol)
{
    std::vector<std::string> candidates;
    candidates.push_back(symbol);
    if (!symbol.empty() && symbol[0] == '_') {
        candidates.push_back(symbol.substr(1));
    } else {
        candidates.push_back("_" + symbol);
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

std::optional<uintptr_t>
lookupMachOSymbol(const std::string& path, uintptr_t load_address, const std::string& symbol)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::nullopt;
    }

    auto header = findMachOHeader(file);
    if (!header) {
        return std::nullopt;
    }

    auto text_and_symtab = findMachOTextAndSymtab(file, *header);
    if (!text_and_symtab) {
        return std::nullopt;
    }

    uint64_t text_vmaddr = text_and_symtab->first;
    const MachOSymtab& symtab = text_and_symtab->second;

    if (symtab.strsize == 0 || symtab.nsyms == 0) {
        return std::nullopt;
    }

    uint64_t strtab_offset = symtab.stroff + header->file_offset;
    std::vector<char> string_table(symtab.strsize);
    if (!readAt(file, strtab_offset, string_table.data(), string_table.size())) {
        return std::nullopt;
    }

    uint64_t sym_entry_size = header->is_64bit ? sizeof(struct nlist_64) : sizeof(struct nlist);
    uint64_t sym_offset = symtab.symoff + header->file_offset;
    const auto candidates = buildSymbolCandidates(symbol);

    for (uint64_t i = 0; i < symtab.nsyms; ++i) {
        uint32_t strx = 0;
        uint8_t n_type = 0;
        uint64_t n_value = 0;

        if (header->is_64bit) {
            struct nlist_64 entry;
            if (!readAt(file, sym_offset, &entry, sizeof(entry))) {
                return std::nullopt;
            }
            strx = entry.n_un.n_strx;
            n_type = entry.n_type;
            n_value = entry.n_value;
        } else {
            struct nlist entry;
            if (!readAt(file, sym_offset, &entry, sizeof(entry))) {
                return std::nullopt;
            }
            strx = entry.n_un.n_strx;
            n_type = entry.n_type;
            n_value = entry.n_value;
        }

        sym_offset += sym_entry_size;

        if (strx == 0 || strx >= string_table.size()) {
            continue;
        }
        if (n_type & N_STAB) {
            continue;
        }

        const char* name = string_table.data() + strx;
        for (const auto& candidate : candidates) {
            if (candidate == name) {
                uintptr_t resolved = 0;
                if (text_vmaddr != 0) {
                    if (n_value < text_vmaddr) {
                        resolved = static_cast<uintptr_t>(load_address + n_value);
                    } else {
                        uintptr_t slide = load_address - text_vmaddr;
                        resolved = static_cast<uintptr_t>(n_value + slide);
                    }
                } else {
                    resolved = static_cast<uintptr_t>(load_address + n_value);
                }
                LOG(DEBUG) << "Mach-O symbol " << candidate << " n_value=0x" << std::hex << n_value
                           << " text_vmaddr=0x" << text_vmaddr << " load=0x" << load_address
                           << " resolved=0x" << resolved << std::dec;
                return resolved;
            }
        }
    }

    return std::nullopt;
}

}  // namespace

MachProcessAnalyzer::MachProcessAnalyzer(pid_t pid)
: AbstractProcessAnalyzer(pid)
{
    auto process_info = AbstractProcessInfo::create();
    auto maps = process_info->getMemoryMaps(pid);

    struct ModuleCandidate
    {
        ModuleInfo info;
        uintptr_t exec_start{0};
        bool has_offset_zero{false};
    };

    std::unordered_map<std::string, ModuleCandidate> modules;
    for (const auto& map : maps) {
        const std::string& path = map.Path();
        if (path.empty()) {
            continue;
        }

        auto it = modules.find(path);
        if (it == modules.end()) {
            ModuleCandidate candidate{};
            candidate.info.path = path;
            candidate.info.name = std::filesystem::path(path).filename().string();
            candidate.info.load_address = map.Start();
            candidate.info.end_address = map.End();
            candidate.has_offset_zero = (map.Offset() == 0);
            if (map.Flags().find("x") != std::string::npos) {
                candidate.exec_start = map.Start();
            }
            it = modules.emplace(path, std::move(candidate)).first;
        } else {
            it->second.info.end_address = std::max(it->second.info.end_address, map.End());
        }

        if (map.Flags().find("x") != std::string::npos) {
            if (it->second.exec_start == 0 || map.Start() < it->second.exec_start) {
                it->second.exec_start = map.Start();
            }
        }

        if (map.Offset() == 0) {
            if (!it->second.has_offset_zero || map.Start() < it->second.info.load_address) {
                it->second.info.load_address = map.Start();
                it->second.has_offset_zero = true;
            }
        } else if (!it->second.has_offset_zero && map.Start() < it->second.info.load_address) {
            it->second.info.load_address = map.Start();
        }
    }

    d_modules.reserve(modules.size());
    for (auto& entry : modules) {
        if (entry.second.exec_start != 0) {
            entry.second.info.load_address = entry.second.exec_start;
        }
        d_modules.push_back(std::move(entry.second.info));
    }
}

std::optional<uintptr_t>
MachProcessAnalyzer::getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const
{
    return lookupMachOSymbol(module.path, module.load_address, symbol);
}

std::vector<ModuleInfo>
MachProcessAnalyzer::getModules() const
{
    return d_modules;
}

std::optional<ModuleInfo>
MachProcessAnalyzer::findModule(const std::string& name) const
{
    for (const auto& module : d_modules) {
        if (module.name == name || module.path == name
            || std::filesystem::path(module.path).filename().string() == name)
        {
            return module;
        }
    }
    return std::nullopt;
}

uintptr_t
MachProcessAnalyzer::getModuleLoadPoint(const ModuleInfo& module) const
{
    return module.load_address;
}

MachCoreFileAnalyzer::MachCoreFileAnalyzer(
        std::string corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
: AbstractCoreFileAnalyzer(std::move(corefile), std::move(executable), std::move(lib_search_path))
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::optional<uintptr_t>
MachCoreFileAnalyzer::getSymbolAddress(const std::string& /* symbol */, const ModuleInfo& /* module */)
        const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::vector<ModuleInfo>
MachCoreFileAnalyzer::getModules() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::optional<ModuleInfo>
MachCoreFileAnalyzer::findModule(const std::string& /* name */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

uintptr_t
MachCoreFileAnalyzer::getModuleLoadPoint(const ModuleInfo& /* module */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::string
MachCoreFileAnalyzer::locateLibrary(const std::string& /* lib */) const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::vector<std::string>
MachCoreFileAnalyzer::getMissingModules() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

pid_t
MachCoreFileAnalyzer::getPid() const
{
    throw std::runtime_error("Core file analyzer not implemented on macOS");
}

std::shared_ptr<AbstractProcessAnalyzer>
AbstractProcessAnalyzer::create(pid_t pid)
{
    return std::make_shared<MachProcessAnalyzer>(pid);
}

std::shared_ptr<AbstractCoreFileAnalyzer>
AbstractCoreFileAnalyzer::create(
        const std::string& corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
{
    return std::make_shared<MachCoreFileAnalyzer>(
            corefile,
            std::move(executable),
            std::move(lib_search_path));
}

}  // namespace pystack
