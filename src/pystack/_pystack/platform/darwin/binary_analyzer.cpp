#include "platform/darwin/binary_analyzer.h"
#include "logging.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>

namespace pystack {

namespace {

struct MachOHeaderInfo
{
    uint64_t file_offset;
    bool is_64bit;
};

struct SectionRecord
{
    std::string segname;
    std::string sectname;
    uint64_t addr;
    uint64_t size;
    uint64_t offset;
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

std::vector<std::string>
buildSectionCandidates(const std::string& name)
{
    std::vector<std::string> candidates;
    if (name.find(',') != std::string::npos) {
        return candidates;
    }
    candidates.push_back(name);
    std::string trimmed = name;
    if (!trimmed.empty() && trimmed[0] == '.') {
        trimmed = trimmed.substr(1);
    }
    if (!trimmed.empty()) {
        candidates.push_back(trimmed);
        candidates.push_back("__" + trimmed);
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

bool
matchesSection(
        const SectionRecord& record,
        const std::optional<std::string>& segname,
        const std::string& sectname)
{
    if (segname.has_value() && record.segname != *segname) {
        return false;
    }
    return record.sectname == sectname;
}

std::optional<std::pair<std::string, std::string>>
parseSectionSpecifier(const std::string& name)
{
    size_t comma = name.find(',');
    if (comma == std::string::npos) {
        return std::nullopt;
    }
    std::string seg = name.substr(0, comma);
    std::string sect = name.substr(comma + 1);
    if (seg.empty() || sect.empty()) {
        return std::nullopt;
    }
    return std::make_pair(seg, sect);
}

struct MachOSections
{
    uint64_t text_vmaddr{0};
    uint64_t min_vmaddr{0};
    std::vector<SectionRecord> records;
};

std::optional<MachOSections>
loadSections(std::ifstream& file, const MachOHeaderInfo& header)
{
    uint64_t header_offset = header.file_offset;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;

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

    MachOSections sections;
    uint64_t cmd_offset = header_offset;
    bool min_vmaddr_set = false;

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
            std::string segname(seg.segname, strnlen(seg.segname, sizeof(seg.segname)));
            if (segname != "__PAGEZERO") {
                if (!min_vmaddr_set || seg.vmaddr < sections.min_vmaddr) {
                    sections.min_vmaddr = seg.vmaddr;
                    min_vmaddr_set = true;
                }
            }
            if (segname == "__TEXT") {
                sections.text_vmaddr = seg.vmaddr;
            }

            uint64_t sect_offset = cmd_offset + sizeof(seg);
            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section_64 sec;
                if (!readAt(file, sect_offset, &sec, sizeof(sec))) {
                    return std::nullopt;
                }
                SectionRecord record;
                record.segname = segname;
                record.sectname = std::string(sec.sectname, strnlen(sec.sectname, sizeof(sec.sectname)));
                record.addr = sec.addr;
                record.size = sec.size;
                record.offset = sec.offset;
                sections.records.push_back(std::move(record));
                sect_offset += sizeof(sec);
            }
        } else if (lc.cmd == LC_SEGMENT && !header.is_64bit) {
            segment_command seg;
            if (!readAt(file, cmd_offset, &seg, sizeof(seg))) {
                return std::nullopt;
            }
            std::string segname(seg.segname, strnlen(seg.segname, sizeof(seg.segname)));
            if (segname != "__PAGEZERO") {
                if (!min_vmaddr_set || seg.vmaddr < sections.min_vmaddr) {
                    sections.min_vmaddr = seg.vmaddr;
                    min_vmaddr_set = true;
                }
            }
            if (segname == "__TEXT") {
                sections.text_vmaddr = seg.vmaddr;
            }

            uint64_t sect_offset = cmd_offset + sizeof(seg);
            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section sec;
                if (!readAt(file, sect_offset, &sec, sizeof(sec))) {
                    return std::nullopt;
                }
                SectionRecord record;
                record.segname = segname;
                record.sectname = std::string(sec.sectname, strnlen(sec.sectname, sizeof(sec.sectname)));
                record.addr = sec.addr;
                record.size = sec.size;
                record.offset = sec.offset;
                sections.records.push_back(std::move(record));
                sect_offset += sizeof(sec);
            }
        }

        if (lc.cmdsize == 0) {
            break;
        }
        cmd_offset += lc.cmdsize;
        if (cmd_offset > header_offset + sizeofcmds) {
            break;
        }
    }

    return sections;
}

std::optional<SectionInfo>
findSectionBySpec(
        const MachOSections& sections,
        const std::string& segment,
        const std::string& section,
        uint64_t image_base)
{
    for (const auto& record : sections.records) {
        if (matchesSection(record, segment, section)) {
            SectionInfo result;
            result.name = section;
            result.flags = "";
            result.addr = static_cast<uintptr_t>(record.addr);
            result.corrected_addr = static_cast<uintptr_t>(record.addr - image_base);
            result.offset = static_cast<off_t>(record.offset);
            result.size = static_cast<size_t>(record.size);
            LOG(DEBUG) << "Mach-O section " << segment << "," << section << " addr=0x" << std::hex
                       << result.addr << " base=0x" << image_base << " corrected=0x"
                       << result.corrected_addr << std::dec;
            return result;
        }
    }

    if (section.find("PyRuntime") != std::string::npos) {
        LOG(DEBUG) << "Mach-O section search failed for " << segment << "," << section;
    }
    return std::nullopt;
}

std::optional<SectionInfo>
findSectionByCandidates(const MachOSections& sections, const std::string& name, uint64_t image_base)
{
    const auto candidates = buildSectionCandidates(name);
    for (const auto& candidate : candidates) {
        for (const auto& record : sections.records) {
            if (matchesSection(record, std::nullopt, candidate)) {
                SectionInfo result;
                result.name = candidate;
                result.flags = "";
                result.addr = static_cast<uintptr_t>(record.addr);
                result.corrected_addr = static_cast<uintptr_t>(record.addr - image_base);
                result.offset = static_cast<off_t>(record.offset);
                result.size = static_cast<size_t>(record.size);
                LOG(DEBUG) << "Mach-O section " << candidate << " addr=0x" << std::hex << result.addr
                           << " base=0x" << image_base << " corrected=0x" << result.corrected_addr
                           << std::dec;
                return result;
            }
        }
    }

    if (name.find("PyRuntime") != std::string::npos) {
        size_t limit = std::min<size_t>(sections.records.size(), 32);
        for (size_t i = 0; i < limit; ++i) {
            LOG(DEBUG) << "Mach-O section candidate: " << sections.records[i].segname << ","
                       << sections.records[i].sectname;
        }
    }
    return std::nullopt;
}

std::optional<std::string>
formatUuid(const uint8_t* uuid)
{
    if (uuid == nullptr) {
        return std::nullopt;
    }
    std::ostringstream stream;
    stream << std::hex;
    for (int i = 0; i < 16; ++i) {
        stream.width(2);
        stream.fill('0');
        stream << static_cast<int>(uuid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            stream << "-";
        }
    }
    return stream.str();
}

}  // namespace

MachOBinaryAnalyzer::MachOBinaryAnalyzer(const std::string& path)
: d_path(path)
{
}

// TODO this function is massive. can we simplify it or break it up?
std::optional<SectionInfo>
MachOBinaryAnalyzer::findSection(const std::string& name) const
{
    std::ifstream file(d_path, std::ios::binary);
    if (!file.is_open()) {
        LOG(ERROR) << "Cannot open Mach-O file " << d_path;
        return std::nullopt;
    }

    auto header = findMachOHeader(file);
    if (!header) {
        LOG(ERROR) << "Unrecognized Mach-O header in " << d_path;
        return std::nullopt;
    }

    auto sections = loadSections(file, *header);
    if (!sections) {
        return std::nullopt;
    }

    uint64_t image_base = sections->text_vmaddr != 0 ? sections->text_vmaddr : sections->min_vmaddr;
    if (image_base == 0) {
        return std::nullopt;
    }

    auto spec = parseSectionSpecifier(name);
    if (spec.has_value()) {
        return findSectionBySpec(*sections, spec->first, spec->second, image_base);
    }

    return findSectionByCandidates(*sections, name, image_base);
}

std::string
MachOBinaryAnalyzer::getBuildId() const
{
    std::ifstream file(d_path, std::ios::binary);
    if (!file.is_open()) {
        LOG(ERROR) << "Cannot open Mach-O file " << d_path;
        return "";
    }

    auto header = findMachOHeader(file);
    if (!header) {
        return "";
    }

    uint64_t header_offset = header->file_offset;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;

    if (header->is_64bit) {
        mach_header_64 mh;
        if (!readAt(file, header_offset, &mh, sizeof(mh))) {
            return "";
        }
        ncmds = mh.ncmds;
        sizeofcmds = mh.sizeofcmds;
        header_offset += sizeof(mh);
    } else {
        mach_header mh;
        if (!readAt(file, header_offset, &mh, sizeof(mh))) {
            return "";
        }
        ncmds = mh.ncmds;
        sizeofcmds = mh.sizeofcmds;
        header_offset += sizeof(mh);
    }

    uint64_t cmd_offset = header_offset;
    for (uint32_t i = 0; i < ncmds; ++i) {
        load_command lc;
        if (!readAt(file, cmd_offset, &lc, sizeof(lc))) {
            return "";
        }
        if (lc.cmd == LC_UUID) {
            uuid_command uc;
            if (!readAt(file, cmd_offset, &uc, sizeof(uc))) {
                return "";
            }
            auto uuid = formatUuid(uc.uuid);
            return uuid.value_or("");
        }
        cmd_offset += lc.cmdsize;
        if (cmd_offset > header_offset + sizeofcmds) {
            break;
        }
    }

    return "";
}

std::unique_ptr<AbstractBinaryAnalyzer>
AbstractBinaryAnalyzer::create(const std::string& path)
{
    return std::make_unique<MachOBinaryAnalyzer>(path);
}

}  // namespace pystack
