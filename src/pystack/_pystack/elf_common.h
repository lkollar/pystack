#pragma once

#include <cstring>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unistd.h>

#include "logging.h"

#ifdef __linux__
#    include <elf.h>
#    include <elfutils/libdwelf.h>
#    include <elfutils/libdwfl.h>
#    include <gelf.h>

namespace pystack {

std::string
parse_permissions(long flags);

class ElfAnalyzerError : public std::exception
{
  public:
    explicit ElfAnalyzerError(std::string error)
    : d_error(std::move(error)){};

    const char* what() const noexcept override
    {
        return d_error.c_str();
    }

  private:
    std::string d_error;
};

// Aliases
using dwfl_unique_ptr = std::unique_ptr<Dwfl, std::function<void(Dwfl*)>>;
using elf_unique_ptr = std::unique_ptr<Elf, std::function<void(Elf*)>>;

// Utility functions for accessing NOTE sections

struct NoteData
{
    Elf* elf{nullptr};
    Elf_Data* data{nullptr};
    Elf64_Xword descriptor_size{0};
    size_t desc_offset{0};
    GElf_Nhdr nhdr{};
};

std::vector<NoteData>
getNoteData(Elf* elf, Elf64_Word note_type, Elf_Type note_data_type);

std::string
buildIdPtrToString(const uint8_t* id, ssize_t size);

std::string
getBuildId(const std::string& filename);

}  // namespace pystack
#endif  // __linux__
