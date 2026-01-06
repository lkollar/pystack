#include "platform/linux/binary_analyzer.h"
#include "compat.h"
#include "elf_common.h"
#include "logging.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <string>

#include <elf.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>
#include <gelf.h>

namespace pystack {

using file_unique_ptr = std::unique_ptr<FILE, std::function<int(FILE*)>>;

ElfBinaryAnalyzer::ElfBinaryAnalyzer(const std::string& path)
: d_path(path)
{
}

std::optional<SectionInfo>
ElfBinaryAnalyzer::findSection(const std::string& section_name) const
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        LOG(ERROR) << "libelf library ELF version too old";
        return std::nullopt;
    }

    LOG(DEBUG) << "Trying to locate " << section_name << " data offset from program headers";
    file_unique_ptr file(fopen(d_path.c_str(), "r"), fclose);
    if (!file || fileno(file.get()) == -1) {
        LOG(ERROR) << "Cannot open ELF file " << d_path;
        return std::nullopt;
    }
    const int fd = fileno(file.get());

    elf_unique_ptr elf = elf_unique_ptr(elf_begin(fd, ELF_C_READ_MMAP, nullptr), elf_end);
    if (!elf) {
        LOG(ERROR) << "Cannot read ELF file " << d_path;
        return std::nullopt;
    }

    Elf* the_elf = elf.get();

    size_t shnum;
    size_t nphdr;
    if (elf_getphdrnum(the_elf, &nphdr) != 0) {
        LOG(ERROR) << "Failed to get program headers";
        return std::nullopt;
    }

    Dwarf_Addr load_point = 0;
    for (size_t i = 0; i < nphdr; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(the_elf, i, &phdr) != &phdr) {
            continue;
        }

        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        load_point = phdr.p_vaddr - phdr.p_vaddr % phdr.p_align;
        LOG(DEBUG) << "Found load point of main Python " << d_path << " at " << std::hex << std::showbase
                   << load_point;
        break;
    }

    if (elf_getshdrnum(the_elf, &shnum) < 0) {
        LOG(ERROR) << "Cannot determine the number of sections in the ELF file";
        return std::nullopt;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(the_elf, &shstrndx) < 0) {
        LOG(ERROR) << "Cannot get the section string table";
        return std::nullopt;
    }

    LOG(DEBUG) << "Found " << shnum << " sections in the ELF file";
    LOG(DEBUG) << "Searching file " << d_path << " for " << section_name << " section";

    if (shnum != 0) {
        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(the_elf, scn)) != nullptr) {
            GElf_Shdr shdr_mem;
            GElf_Shdr* shdr = gelf_getshdr(scn, &shdr_mem);
            if (shdr == nullptr) {
                continue;
            }
            const char* sname = elf_strptr(the_elf, shstrndx, shdr->sh_name) ?: "<corrupt>";
            LOG(DEBUG) << "Section found with name: " << sname;
            if (sname == nullptr || std::string(sname) != section_name) {
                continue;
            }
            LOG(DEBUG) << "Found " << section_name << " section with offset " << std::hex
                       << std::showbase << shdr->sh_addr;

            SectionInfo result;
            result.name = section_name;
            result.flags = parse_permissions(shdr->sh_flags);
            result.addr = shdr->sh_addr;
            result.corrected_addr = shdr->sh_addr - load_point;
            result.offset = shdr->sh_offset;
            result.size = shdr->sh_size;
            return result;
        }
    }
    return std::nullopt;
}

// getBuildId is implemented in elf_common.cpp and used by both corefile.cpp and ElfBinaryAnalyzer
std::string
ElfBinaryAnalyzer::getBuildId() const
{
    return pystack::getBuildId(d_path);
}

// Factory method implementation for Linux
std::unique_ptr<AbstractBinaryAnalyzer>
AbstractBinaryAnalyzer::create(const std::string& path)
{
    return std::make_unique<ElfBinaryAnalyzer>(path);
}

}  // namespace pystack
