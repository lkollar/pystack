#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <string>
#include <system_error>
#include <unistd.h>

#include "platform/linux/process_info.h"
#include "platform/process_info_parser.h"

namespace fs = std::filesystem;

namespace pystack {

std::string
LinuxProcessInfo::getExecutablePath(pid_t pid) const
{
    fs::path proc_path = fs::path("/proc") / std::to_string(pid) / "exe";
    char buf[PATH_MAX];
    ssize_t len = readlink(proc_path.c_str(), buf, sizeof(buf) - 1);
    if (len == -1) {
        throw std::ios_base::failure("Failed to read executable path");
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
        throw std::ios_base::failure("Failed to open " + maps_path.string());
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parseProcMaps(buffer.str());
}

std::unique_ptr<AbstractProcessInfo>
AbstractProcessInfo::create()
{
    return std::make_unique<LinuxProcessInfo>();
}

}  // namespace pystack
