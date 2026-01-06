#include <cassert>
#include <cerrno>
#include <cstring>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <string>
#include <utility>

#include "compat.h"
#include "elf_common.h"

namespace pystack {

using file_unique_ptr = std::unique_ptr<FILE, std::function<int(FILE*)>>;

int
pystack_find_elf(
        Dwfl_Module* mod,
        void** userdata,
        const char* modname,
        Dwarf_Addr base,
        char** file_name,
        Elf** elfp)
{
    const char* the_modname = (modname == nullptr) ? "???" : modname;
    int ret = dwfl_build_id_find_elf(mod, userdata, modname, base, file_name, elfp);
    if (ret > 0) {
        const char* the_filename = (*file_name == nullptr) ? "???" : *file_name;
        LOG(DEBUG) << "Located debug info for " << the_modname << " using BUILD ID in " << the_filename;
        return ret;
    }
    ret = dwfl_linux_proc_find_elf(mod, userdata, modname, base, file_name, elfp);
    if (file_name == nullptr) {
        LOG(DEBUG) << "Could not locate debug info for " << the_modname;
    } else {
        LOG(DEBUG) << "Located debug info for " << the_modname << " by path in " << *file_name;
    }
    return ret;
}

std::string
parse_permissions(long flags)
{
    std::string perms;
    if (flags & PF_R) {
        perms += "r";
    }
    if (flags & PF_W) {
        perms += "w";
    }
    if (flags & PF_X) {
        perms += "x";
    }
    return perms;
}

static std::vector<NoteData>
getDataFromNoteSection(
        Elf* elf,
        Elf64_Word note_type,
        Elf_Type note_data_type,
        const GElf_Phdr* program_header,
        Elf_Data* data)
{
    size_t note_offset = 0;
    size_t name_offset = 0;
    size_t desc_offset = 0;
    GElf_Nhdr note_contents;
    auto is_note_of_desired_type = [](const char* name, Elf64_Word type, GElf_Nhdr nhdr) -> bool {
        return nhdr.n_type == type && (nhdr.n_namesz == 4 || (nhdr.n_namesz == 5 && name[4] == '\0'))
               && !::memcmp(name, "CORE", 4);
    };

    std::vector<NoteData> result;

    while (note_offset < data->d_size) {
        note_offset = gelf_getnote(data, note_offset, &note_contents, &name_offset, &desc_offset);
        if (note_offset <= 0) {
            break;
        }

        const char* note_name = note_contents.n_namesz == 0 ? "" : (char*)(data->d_buf) + name_offset;
        if (!is_note_of_desired_type(note_name, note_type, note_contents)) {
            LOG(DEBUG) << "Skipping NOTE segment with name " << note_name << " and type "
                       << note_contents.n_type;
            continue;
        }

        const GElf_Word descr_size = note_contents.n_descsz;
        const GElf_Off descr_location = program_header->p_offset + desc_offset;
        Elf_Data* note_data = elf_getdata_rawchunk(elf, descr_location, descr_size, note_data_type);
        if (note_data == nullptr) {
            LOG(WARNING) << "Invalid auxiliary NOTE data found in core file";
            continue;
        }

        LOG(DEBUG) << "Found NOTE of type " << note_type << " with name '" << note_name
                   << "' at position " << std::hex << std::showbase << descr_location;

        result.emplace_back(NoteData{elf, note_data, descr_size, desc_offset, note_contents});
    }
    if (result.empty()) {
        LOG(DEBUG) << "Failed to locate NOTE of type " << note_type << " in the core file";
    }
    return result;
}

std::vector<NoteData>
getNoteData(Elf* elf, Elf64_Word note_type, Elf_Type note_data_type)
{
    LOG(DEBUG) << "Searching for NOTE segments of type " << note_type;
    size_t n_program_headers;
    if (elf_getphdrnum(elf, &n_program_headers) < 0) {
        LOG(ERROR) << "Cannot determine number of program headers in the ELF file";
        return {};
    }

    for (size_t program_header_idx = 0; program_header_idx < n_program_headers; ++program_header_idx) {
        GElf_Phdr mem;
        const GElf_Phdr* program_header = gelf_getphdr(elf, program_header_idx, &mem);

        if (program_header == nullptr || program_header->p_type != PT_NOTE) {
            continue;
        }
        LOG(DEBUG) << "Program header of type PT_NOTE found with offset " << std::hex << std::showbase
                   << program_header->p_offset;
        Elf_Data* data = elf_getdata_rawchunk(
                elf,
                program_header->p_offset,
                program_header->p_filesz,
                ELF_T_NHDR);

        if (data == nullptr) {
            LOG(WARNING) << "Invalid data in NOTE section at " << std::showbase << std::hex
                         << program_header->p_offset;
            continue;
        }

        LOG(DEBUG) << "Fetching data from NOTE segments of type " << note_type
                   << " in program header with offset " << std::hex << std::showbase
                   << program_header->p_offset;
        return getDataFromNoteSection(elf, note_type, note_data_type, program_header, data);
    }
    LOG(ERROR) << "Failed to locate a program header of type PT_NOTE in the core file";
    return {};
}

std::string
buildIdPtrToString(const uint8_t* id, ssize_t size)
{
    std::stringstream result;
    do {
        result << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(*id++);
    } while (--size > 0);
    return result.str();
}

std::string
getBuildId(const std::string& filename)
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        LOG(ERROR) << "libelf library ELF version too old";
        return "";
    }

    if (!fs::exists(filename)) {
        LOG(DEBUG) << filename << " does not exist";
        return "";
    }

    LOG(DEBUG) << "Trying to locate Build ID from binary " << filename;
    file_unique_ptr file(fopen(filename.c_str(), "r"), fclose);
    if (!file || fileno(file.get()) == -1) {
        LOG(ERROR) << "Cannot open ELF file " << filename;
        return "";
    }
    const int fd = fileno(file.get());

    elf_unique_ptr elf = elf_unique_ptr(elf_begin(fd, ELF_C_READ_MMAP, nullptr), elf_end);
    if (!elf) {
        LOG(ERROR) << "Cannot read ELF file " << filename;
        return "";
    }

    Elf* the_elf = elf.get();

    const void* build_idp = nullptr;
    ssize_t elf_build_id_len = dwelf_elf_gnu_build_id(the_elf, &build_idp);
    if (elf_build_id_len <= 0) {
        return "";
    }
    return buildIdPtrToString(reinterpret_cast<const unsigned char*>(build_idp), elf_build_id_len);
}

}  // namespace pystack
