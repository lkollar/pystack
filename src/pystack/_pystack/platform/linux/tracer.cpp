#include "tracer.h"

#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unordered_map>
#include <vector>

#include "logging.h"

namespace {

static const std::string PERM_MESSAGE = "Operation not permitted";

class DirectoryReader
{
  public:
    explicit DirectoryReader(const std::string& path)
    : dir_(opendir(path.c_str()))
    {
        if (!dir_) {
            throw std::runtime_error("Could not read the contents of " + path);
        }
    };

    ~DirectoryReader()
    {
        closedir(dir_);
    };

    std::vector<std::string> files() const
    {
        std::vector<std::string> result;
        struct dirent* ent;
        while ((ent = readdir(dir_)) != nullptr) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
                continue;
            }
            result.emplace_back(ent->d_name);
        }
        return result;
    }

  private:
    DIR* dir_;
};

}  // namespace

namespace pystack {

static std::vector<int>
getProcessTids(pid_t pid)
{
    std::string filepath = "/proc/" + std::to_string(pid) + "/task";
    ::DirectoryReader reader(filepath);
    std::vector<std::string> files = reader.files();
    std::vector<int> tids;
    std::transform(
            files.cbegin(),
            files.cend(),
            std::back_inserter(tids),
            [](const std::string& file) -> int { return std::stoi(file); });
    return tids;
}

LinuxProcessTracer::LinuxProcessTracer(pid_t pid)
{
    std::unordered_map<int, int> error_by_tid;

    bool found_new_tid = true;
    while (found_new_tid) {
        found_new_tid = false;

        auto tids = getProcessTids(pid);
        for (auto& tid : tids) {
            if (d_tids.count(tid)) {
                continue;  // already stopped
            }

            auto err_it = error_by_tid.find(tid);
            if (err_it != error_by_tid.end()) {
                // We got an error for this TID on the last iteration.
                // Since we found the TID again this iteration, it still
                // belongs to us and should have been stoppable.
                detachFromProcess();

                int error = err_it->second;
                if (error == EPERM) {
                    throw std::runtime_error(PERM_MESSAGE);
                }
                throw std::system_error(error, std::generic_category());
            }

            found_new_tid = true;

            LOG(INFO) << "Trying to stop thread " << tid;
            long ret = ptrace(PTRACE_ATTACH, tid, nullptr, nullptr);
            if (ret < 0) {
                int error = errno;
                LOG(WARNING) << "Failed to attach to thread " << tid << ": " << strerror(error);
                error_by_tid.emplace(tid, error);
                continue;
            }

            // Add each tid as we attach: these are the tids we detach from.
            d_tids.insert(tid);

            LOG(INFO) << "Waiting for thread " << tid << " to be stopped";
            ret = waitpid(tid, nullptr, WUNTRACED);
            if (ret < 0) {
                // In some old kernels is not possible to use WUNTRACED with
                // threads (only the main thread will return a non zero value).
                if (tid == pid || errno != ECHILD) {
                    detachFromProcess();
                }
            }
            LOG(INFO) << "Thread " << tid << " stopped";
        }
    }
    LOG(INFO) << "All " << d_tids.size() << " threads stopped";
}

void
LinuxProcessTracer::detachFromProcess()
{
    for (auto& tid : d_tids) {
        LOG(INFO) << "Detaching from thread " << tid;
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

LinuxProcessTracer::~LinuxProcessTracer()
{
    detachFromProcess();
}

std::vector<int>
LinuxProcessTracer::getTids() const
{
    return {d_tids.begin(), d_tids.end()};
}

}  // namespace pystack
