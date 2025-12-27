#include "process_info.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace pystack {

std::string
LinuxProcessInfo::getExecutablePath(pid_t pid) const
{
    fs::path proc_path = fs::path("/proc") / std::to_string(pid) / "exe";
    char buf[PATH_MAX];
    ssize_t len = readlink(proc_path.c_str(), buf, sizeof(buf) - 1);
    if (len == -1) {
        throw std::runtime_error("Failed to read executable path: " + std::string(strerror(errno)));
    }
    buf[len] = '\0';
    return std::string(buf);
}

std::string
LinuxProcessInfo::getThreadName(pid_t pid, int tid) const
{
    fs::path comm_path = fs::path("/proc") / std::to_string(pid) / "task" / std::to_string(tid) / "comm";
    std::ifstream file(comm_path);
    if (!file) {
        return "";  // Thread may have exited
    }
    std::string name;
    std::getline(file, name);
    return name;
}

bool
LinuxProcessInfo::processExists(pid_t pid) const
{
    fs::path proc_path = fs::path("/proc") / std::to_string(pid);
    return fs::exists(proc_path);
}

std::vector<VirtualMap>
LinuxProcessInfo::getMemoryMaps(pid_t pid) const
{
    fs::path maps_path = fs::path("/proc") / std::to_string(pid) / "maps";
    std::ifstream file(maps_path);
    if (!file) {
        throw std::runtime_error("Failed to open " + maps_path.string());
    }

    std::vector<VirtualMap> maps;
    std::string line;

    while (std::getline(file, line)) {
        // Format: start-end perms offset dev inode pathname
        // Example: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/foo
        uintptr_t start, end;
        char perms[5];
        unsigned long offset;
        char dev[12];
        unsigned long inode;
        char pathname[PATH_MAX] = "";

        int matched = sscanf(
                line.c_str(),
                "%lx-%lx %4s %lx %11s %lu %[^\n]",
                &start,
                &end,
                perms,
                &offset,
                dev,
                &inode,
                pathname);

        if (matched < 6) {
            continue;  // Skip malformed lines
        }

        maps.emplace_back(
                start,
                end,
                end - start,  // filesize
                std::string(perms),
                offset,
                std::string(dev),
                inode,
                std::string(pathname));
    }

    return maps;
}

}  // namespace pystack
