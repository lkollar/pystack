#include "platform/linux/analyzer.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <sstream>

#include "analyzer.h"
#include "compat.h"
#include "elf_common.h"
#include "logging.h"

namespace pystack {

namespace {

ModuleInfo
makeModuleInfo(Dwfl_Module* mod)
{
    Dwarf_Addr start = 0;
    Dwarf_Addr end = 0;
    const char* mainfile = nullptr;
    const char* debugfile = nullptr;
    const char* modname =
            dwfl_module_info(mod, nullptr, &start, &end, nullptr, nullptr, &mainfile, &debugfile);

    std::string path;
    if (mainfile != nullptr) {
        path = mainfile;
    } else if (debugfile != nullptr) {
        path = debugfile;
    } else if (modname != nullptr) {
        path = modname;
    }

    std::string name =
            path.empty() ? (modname ? modname : "") : std::filesystem::path(path).filename().string();

    std::optional<std::string> build_id = std::nullopt;
    const unsigned char* id = nullptr;
    GElf_Addr id_vaddr = 0;
    int ret = dwfl_module_build_id(mod, &id, &id_vaddr);
    if (ret > 0) {
        build_id = buildIdPtrToString(id, ret);
    }

    return ModuleInfo{name, path, start, end, build_id};
}

struct SymbolLookupArg
{
    const char* symbol;
    const ModuleInfo* module;
    uintptr_t addr;
};

static int
module_symbol_callback(
        Dwfl_Module* mod,
        void** userdata __attribute__((unused)),
        const char* name __attribute__((unused)),
        Dwarf_Addr start,
        void* arg)
{
    auto* args = static_cast<SymbolLookupArg*>(arg);
    if (args->addr != 0) {
        return DWARF_CB_ABORT;
    }

    Dwarf_Addr end = 0;
    const char* mainfile = nullptr;
    const char* debugfile = nullptr;
    const char* modname =
            dwfl_module_info(mod, nullptr, &start, &end, nullptr, nullptr, &mainfile, &debugfile);

    const std::string mod_path =
            mainfile ? mainfile : (debugfile ? debugfile : (modname ? modname : ""));
    const bool matches_range = start == args->module->load_address && end == args->module->end_address;
    const bool matches_path = !args->module->path.empty() && args->module->path == mod_path;

    if (!matches_range && !matches_path) {
        return DWARF_CB_OK;
    }

    int n_syms = dwfl_module_getsymtab(mod);
    if (n_syms == -1) {
        return DWARF_CB_OK;
    }

    GElf_Sym sym;
    GElf_Addr addr;
    for (int i = 0; i < n_syms; i++) {
        const char* sname = dwfl_module_getsym_info(mod, i, &sym, &addr, nullptr, nullptr, nullptr);
        if (sname != nullptr && std::strcmp(sname, args->symbol) == 0) {
            args->addr = addr;
            return DWARF_CB_ABORT;
        }
    }

    return DWARF_CB_OK;
}

}  // namespace

DwflProcessAnalyzer::DwflProcessAnalyzer(pid_t pid)
: AbstractProcessAnalyzer(pid)
, d_dwfl(nullptr)
, d_debuginfo_path(nullptr)
, d_callbacks()
{
    std::memset(&d_callbacks, 0, sizeof(d_callbacks));
    d_callbacks.find_elf = pystack_find_elf;
    d_callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    d_callbacks.debuginfo_path = &d_debuginfo_path;

    d_dwfl = dwfl_unique_ptr(dwfl_begin(&d_callbacks), dwfl_end);

    if (!d_dwfl) {
        throw ElfAnalyzerError("Failed to initialize DWARF analyzer");
    }

    if (dwfl_linux_proc_report(d_dwfl.get(), pid) || dwfl_report_end(d_dwfl.get(), nullptr, nullptr)) {
        throw ElfAnalyzerError("Failed to analyze DWARF information for the remote process");
    }

    if (dwfl_linux_proc_attach(d_dwfl.get(), pid, true) != 0) {
        throw ElfAnalyzerError("Could not attach the DWARF process analyzer");
    }
}

std::optional<uintptr_t>
DwflProcessAnalyzer::getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const
{
    SymbolLookupArg args{symbol.c_str(), &module, 0};
    if (dwfl_getmodules(d_dwfl.get(), module_symbol_callback, &args, 0) != 0) {
        throw ElfAnalyzerError("Failed to fetch modules");
    }
    if (args.addr == 0) {
        return std::nullopt;
    }
    return args.addr;
}

std::vector<ModuleInfo>
DwflProcessAnalyzer::getModules() const
{
    std::vector<ModuleInfo> modules;
    auto callback = [](Dwfl_Module* mod,
                       void** userdata __attribute__((unused)),
                       const char* name __attribute__((unused)),
                       Dwarf_Addr start __attribute__((unused)),
                       void* arg) -> int {
        auto* mods = static_cast<std::vector<ModuleInfo>*>(arg);
        mods->push_back(makeModuleInfo(mod));
        return DWARF_CB_OK;
    };

    if (dwfl_getmodules(d_dwfl.get(), callback, &modules, 0) != 0) {
        throw ElfAnalyzerError("Failed to fetch modules");
    }
    return modules;
}

std::optional<ModuleInfo>
DwflProcessAnalyzer::findModule(const std::string& name) const
{
    auto modules = getModules();
    for (const auto& module : modules) {
        if (module.name == name || module.path == name) {
            return module;
        }
    }
    return std::nullopt;
}

uintptr_t
DwflProcessAnalyzer::getModuleLoadPoint(const ModuleInfo& module) const
{
    return module.load_address;
}

DwflCoreFileAnalyzer::DwflCoreFileAnalyzer(
        std::string corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
: AbstractCoreFileAnalyzer(std::move(corefile), std::move(executable), std::move(lib_search_path))
, d_dwfl(nullptr)
, d_debuginfo_path(nullptr)
, d_callbacks()
, d_fd(0)
, d_pid(0)
, d_elf(nullptr)
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        throw ElfAnalyzerError("libelf library ELF version too old");
    }

    d_fd = open(d_filename.c_str(), O_RDONLY);
    if (d_fd == -1) {
        throw ElfAnalyzerError(
                "Failed to open ELF file '" + d_filename + "' (" + std::strerror(errno) + ")");
    }

    d_elf = elf_unique_ptr(elf_begin(d_fd, ELF_C_READ_MMAP, nullptr), elf_end);
    if (!d_elf) {
        close(d_fd);
        throw ElfAnalyzerError("Cannot read elf file");
    }

    std::memset(&d_callbacks, 0, sizeof(d_callbacks));
    d_callbacks.find_elf = pystack_find_elf;
    d_callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    d_callbacks.debuginfo_path = &d_debuginfo_path;

    d_dwfl = dwfl_unique_ptr(dwfl_begin(&d_callbacks), dwfl_end);

    if (!d_dwfl) {
        throw ElfAnalyzerError("Failed to initialize core analyzer");
    }

    const char* the_executable = d_executable.has_value() ? d_executable.value().c_str() : nullptr;

    if (dwfl_core_file_report(d_dwfl.get(), d_elf.get(), the_executable) < 0
        || dwfl_report_end(d_dwfl.get(), nullptr, nullptr) != 0)
    {
        throw ElfAnalyzerError(
                "Failed to analyze DWARF information for the core file. '" + d_filename
                + "' doesn't look like a valid core file.");
    }

    resolveLibraries();

    int result = dwfl_core_file_attach(d_dwfl.get(), d_elf.get());
    if (result < 0) {
        throw ElfAnalyzerError(
                "Could not attach the core map analyzer. '" + d_filename
                + "' doesn't look like a valid core file.");
    }
    d_pid = result;
}

DwflCoreFileAnalyzer::~DwflCoreFileAnalyzer()
{
    close(d_fd);
}

std::optional<uintptr_t>
DwflCoreFileAnalyzer::getSymbolAddress(const std::string& symbol, const ModuleInfo& module) const
{
    SymbolLookupArg args{symbol.c_str(), &module, 0};
    if (dwfl_getmodules(d_dwfl.get(), module_symbol_callback, &args, 0) != 0) {
        throw ElfAnalyzerError("Failed to fetch modules");
    }
    if (args.addr == 0) {
        return std::nullopt;
    }
    return args.addr;
}

std::vector<ModuleInfo>
DwflCoreFileAnalyzer::getModules() const
{
    std::vector<ModuleInfo> modules;
    auto callback = [](Dwfl_Module* mod,
                       void** userdata __attribute__((unused)),
                       const char* name __attribute__((unused)),
                       Dwarf_Addr start __attribute__((unused)),
                       void* arg) -> int {
        auto* mods = static_cast<std::vector<ModuleInfo>*>(arg);
        mods->push_back(makeModuleInfo(mod));
        return DWARF_CB_OK;
    };

    if (dwfl_getmodules(d_dwfl.get(), callback, &modules, 0) != 0) {
        throw ElfAnalyzerError("Failed to fetch modules");
    }
    return modules;
}

std::optional<ModuleInfo>
DwflCoreFileAnalyzer::findModule(const std::string& name) const
{
    auto modules = getModules();
    for (const auto& module : modules) {
        if (module.name == name || module.path == name) {
            return module;
        }
    }
    return std::nullopt;
}

uintptr_t
DwflCoreFileAnalyzer::getModuleLoadPoint(const ModuleInfo& module) const
{
    return module.load_address;
}

std::string
DwflCoreFileAnalyzer::locateLibrary(const std::string& lib) const
{
    if (!d_lib_search_path) {
        return lib;
    }
    LOG(DEBUG) << "Searching for module: " << lib;
    std::string dir_to_consider;
    const std::filesystem::path target{lib};
    std::stringstream stream{d_lib_search_path.value()};
    while (std::getline(stream, dir_to_consider, ':')) {
        if (!std::filesystem::exists(dir_to_consider) || !std::filesystem::is_directory(dir_to_consider))
        {
            continue;
        }
        for (const auto& entry : std::filesystem::directory_iterator(dir_to_consider)) {
            if (entry.path().filename() != target.filename()) {
                continue;
            }
            if (std::filesystem::is_regular_file(entry)) {
                LOG(DEBUG) << "Module " << lib << " found at " << entry.path().string();
                return entry.path().string();
            }
        }
    }
    LOG(DEBUG) << "Could not locate module " << lib << " in the search path";
    return lib;
}

std::vector<std::string>
DwflCoreFileAnalyzer::getMissingModules() const
{
    return d_missing_modules;
}

pid_t
DwflCoreFileAnalyzer::getPid() const
{
    return d_pid;
}

void
DwflCoreFileAnalyzer::removeModuleIf(std::function<bool(Dwfl_Module*)> predicate) const
{
    using Predicate = decltype(predicate);
    struct CallbackArgs
    {
        Dwfl* dwfl;
        Predicate& predicate;
    } callback_args = {d_dwfl.get(), predicate};

    dwfl_report_begin(d_dwfl.get());

    int const rc = dwfl_report_end(
            d_dwfl.get(),
            [](Dwfl_Module* mod, void*, const char* name, Dwarf_Addr start, void* arg) -> int {
                auto& callback_args = *static_cast<CallbackArgs*>(arg);
                if (!callback_args.predicate(mod)) {
                    Dwarf_Addr end;
                    dwfl_module_info(mod, nullptr, nullptr, &end, nullptr, nullptr, nullptr, nullptr);
                    if (!dwfl_report_module(callback_args.dwfl, name, start, end)) {
                        throw ElfAnalyzerError(
                                std::string("Unexpected error retaining DWARF module: ")
                                + dwfl_errmsg(dwfl_errno()));
                    }
                }
                return 0;
            },
            &callback_args);

    if (0 != rc) {
        throw ElfAnalyzerError(
                std::string("Unexpected error while filtering DWARF modules: ")
                + dwfl_errmsg(dwfl_errno()));
    }
}

void
DwflCoreFileAnalyzer::resolveLibraries()
{
    struct RemappedModule
    {
        std::string modname;
        std::string path;
        GElf_Addr addr;
    };
    std::vector<RemappedModule> remapped_modules;

    LOG(DEBUG) << "Searching for missing and mismapped modules";
    removeModuleIf([this, &remapped_modules](Dwfl_Module* mod) -> bool {
        Dwarf_Addr start, end;
        const char* path;
        const char* modname =
                dwfl_module_info(mod, nullptr, &start, &end, nullptr, nullptr, &path, nullptr);
        if (!path) {
            path = modname;
        }

        std::string located_path;
        bool searched;
        if (!d_executable || !d_lib_search_path) {
            located_path = path;
            searched = false;
        } else {
            located_path = locateLibrary(path);
            searched = true;
        }
        bool const located_path_exists = std::filesystem::exists(located_path);

        if (!located_path_exists) {
            LOG(DEBUG) << "Adding " << path << " as a missing module "
                       << (searched ? "despite" : "without") << " a search";
            d_missing_modules.emplace_back(located_path);
        }

        if (located_path_exists && located_path != path) {
            std::string const filename = std::filesystem::path(located_path).filename().string();
            remapped_modules.push_back({filename, located_path, start});
            LOG(DEBUG) << "Dropping module " << path << " spanning from " << std::hex << std::showbase
                       << start << " to " << end << " so that it can be remapped from " << located_path;
            return true;
        } else {
            LOG(DEBUG) << "Retaining module " << path << " spanning from " << std::hex << std::showbase
                       << start << " to " << end;
            return false;
        }
    });

    LOG(DEBUG) << "Re-adding " << remapped_modules.size()
               << " mismapped modules with corrected locations";
    for (const auto& module : remapped_modules) {
        if (!dwfl_report_elf(
                    d_dwfl.get(),
                    module.modname.c_str(),
                    module.path.c_str(),
                    -1,
                    module.addr,
                    false))
        {
            LOG(ERROR) << "Failed to report module " << module.modname << ": "
                       << dwfl_errmsg(dwfl_errno());
            throw ElfAnalyzerError("Failed to report ELF modules for core file");
        } else {
            LOG(DEBUG) << "Reported module " << module.modname << " with path " << module.path
                       << " starting at " << std::hex << std::showbase << module.addr;
        }
    }

    LOG(DEBUG) << "Completing reporting of modules";
    if (dwfl_report_end(d_dwfl.get(), nullptr, nullptr) != 0) {
        throw ElfAnalyzerError(
                std::string("Unexpected error from dwfl_report_end: ") + dwfl_errmsg(dwfl_errno()));
    }
}

std::shared_ptr<AbstractProcessAnalyzer>
AbstractProcessAnalyzer::create(pid_t pid)
{
    return std::make_shared<DwflProcessAnalyzer>(pid);
}

std::shared_ptr<AbstractCoreFileAnalyzer>
AbstractCoreFileAnalyzer::create(
        const std::string& corefile,
        std::optional<std::string> executable,
        std::optional<std::string> lib_search_path)
{
    return std::make_shared<DwflCoreFileAnalyzer>(
            corefile,
            std::move(executable),
            std::move(lib_search_path));
}

}  // namespace pystack
