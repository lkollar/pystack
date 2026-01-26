#include "platform/process_info_parser.h"

#include <limits.h>
#include <sstream>

#include "logging.h"

namespace pystack {

std::vector<VirtualMap>
parseProcMaps(const std::string& content)
{
    std::vector<VirtualMap> maps;
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        // Format: start-end perms offset dev inode pathname
        uintptr_t start, end;
        char perms[5];
        unsigned long offset;
        char dev[12];
        unsigned long inode;
        char pathname[PATH_MAX] = "";

        int matched =
                sscanf(line.c_str(),
                       "%lx-%lx %4s %lx %11s %lu %[^\n]",
                       &start,
                       &end,
                       perms,
                       &offset,
                       dev,
                       &inode,
                       pathname);

        if (matched < 6) {
            LOG(DEBUG) << "Line cannot be recognized: " << line;
            continue;
        }

        maps.emplace_back(
                start,
                end,
                end - start,
                std::string(perms),
                offset,
                std::string(dev),
                inode,
                std::string(pathname));
    }

    return maps;
}

}  // namespace pystack
