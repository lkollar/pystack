#pragma once

#include <string>
#include <vector>

#include "mem.h"

namespace pystack {

std::vector<VirtualMap>
parseProcMaps(const std::string& content);

}  // namespace pystack
