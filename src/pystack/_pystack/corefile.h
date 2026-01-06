#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "analyzer.h"
#include "mem.h"

namespace pystack {

#ifdef __linux__

class DwflCoreFileAnalyzer;

struct CoreCrashInfo
{
    int si_signo;
    int si_errno;
    int si_code;
    int sender_pid;
    int sender_uid;
    uintptr_t failed_addr;
};

static const size_t FNAME_SIZE = 16;
static const size_t PSARGS_SIZE = 80;

struct CorePsInfo
{
    char state;
    char sname;
    char zomb;
    char nice;
    ulong flag;
    int uid;
    int gid;
    pid_t pid;
    pid_t ppid;
    pid_t pgrp;
    pid_t sid;
    char fname[FNAME_SIZE];
    char psargs[PSARGS_SIZE];
};

class CoreAnalyzerError : public std::exception
{
  public:
    explicit CoreAnalyzerError(std::string error)
    : d_error(std::move(error)){};

    [[nodiscard]] const char* what() const noexcept override
    {
        return d_error.c_str();
    }

  private:
    std::string d_error;
};

// This is a struct so cython can convert easily from this
struct CoreVirtualMap
{
    // Data members
    uintptr_t start;
    uintptr_t end;
    unsigned long filesize;
    std::string flags;
    unsigned long offset;
    std::string device;
    unsigned long inode;
    std::string path;
    std::string buildid;
};

class CoreFileExtractor
{
  public:
    // Constructors
    explicit CoreFileExtractor(std::shared_ptr<AbstractCoreFileAnalyzer> analyzer);

    // Methods
    std::vector<CoreVirtualMap> MemoryMaps() const;
    std::vector<SimpleVirtualMap> ModuleInformation() const;
    pid_t Pid() const;
    std::string extractExecutable() const;
    CoreCrashInfo extractFailureInfo() const;
    CorePsInfo extractPSInfo() const;
    const std::vector<CoreVirtualMap> extractMappedFiles() const;
    std::vector<std::string> missingModules() const;

  private:
    // Data members
    std::shared_ptr<AbstractCoreFileAnalyzer> d_analyzer;
    std::shared_ptr<DwflCoreFileAnalyzer> d_dwfl_analyzer;
    std::vector<SimpleVirtualMap> d_module_info;
    std::vector<CoreVirtualMap> d_maps;

    // Methods
    void populateMaps();
    uintptr_t findExecFn() const;
};

#else  // !__linux__ (Darwin stubs)

struct CoreCrashInfo
{
    int si_signo = 0;
    int si_errno = 0;
    int si_code = 0;
    int sender_pid = 0;
    int sender_uid = 0;
    uintptr_t failed_addr = 0;
};

static const size_t FNAME_SIZE = 16;
static const size_t PSARGS_SIZE = 80;

struct CorePsInfo
{
    char state = 0;
    char sname = 0;
    char zomb = 0;
    char nice = 0;
    unsigned long flag = 0;
    int uid = 0;
    int gid = 0;
    pid_t pid = 0;
    pid_t ppid = 0;
    pid_t pgrp = 0;
    pid_t sid = 0;
    char fname[FNAME_SIZE] = {};
    char psargs[PSARGS_SIZE] = {};
};

struct CoreVirtualMap
{
    uintptr_t start = 0;
    uintptr_t end = 0;
    unsigned long filesize = 0;
    std::string flags;
    unsigned long offset = 0;
    std::string device;
    unsigned long inode = 0;
    std::string path;
    std::string buildid;
};

class CoreFileExtractor
{
  public:
    explicit CoreFileExtractor(std::shared_ptr<AbstractCoreFileAnalyzer> /* analyzer */)
    {
        throw std::runtime_error("CoreFileExtractor not implemented on macOS");
    }

    std::vector<CoreVirtualMap> MemoryMaps() const
    {
        return {};
    }
    std::vector<SimpleVirtualMap> ModuleInformation() const
    {
        return {};
    }
    pid_t Pid() const
    {
        return 0;
    }
    std::string extractExecutable() const
    {
        return "";
    }
    CoreCrashInfo extractFailureInfo() const
    {
        return {};
    }
    CorePsInfo extractPSInfo() const
    {
        return {};
    }
    const std::vector<CoreVirtualMap> extractMappedFiles() const
    {
        return {};
    }
    std::vector<std::string> missingModules() const
    {
        return {};
    }
};

#endif  // __linux__

}  // namespace pystack
