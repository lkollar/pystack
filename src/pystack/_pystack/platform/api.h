#pragma once

#include <unistd.h>
#include <vector>

std::vector<int>
getProcessTids(pid_t pid);
