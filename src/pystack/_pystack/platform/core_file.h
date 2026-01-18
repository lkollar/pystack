#pragma once

#include <memory>
#include <string>
#include <vector>

#include "analyzer.h"
#include "mem.h"

namespace pystack {

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
    unsigned long flag;
    int uid;
    int gid;
    pid_t pid;
    pid_t ppid;
    pid_t pgrp;
    pid_t sid;
    char fname[FNAME_SIZE];
    char psargs[PSARGS_SIZE];
};

// This is a struct so cython can convert easily from this
struct CoreVirtualMap
{
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

class AbstractCoreFileExtractor
{
  public:
    virtual ~AbstractCoreFileExtractor() = default;

    virtual std::vector<CoreVirtualMap> MemoryMaps() const = 0;
    virtual std::vector<SimpleVirtualMap> ModuleInformation() const = 0;
    virtual pid_t Pid() const = 0;
    virtual std::string extractExecutable() const = 0;
    virtual CoreCrashInfo extractFailureInfo() const = 0;
    virtual CorePsInfo extractPSInfo() const = 0;
    virtual std::vector<CoreVirtualMap> extractMappedFiles() const = 0;
    virtual std::vector<std::string> missingModules() const = 0;

    static std::unique_ptr<AbstractCoreFileExtractor>
    create(std::shared_ptr<AbstractCoreFileAnalyzer> analyzer);
};

}  // namespace pystack
