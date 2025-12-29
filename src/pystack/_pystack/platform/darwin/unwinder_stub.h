// Stub unwinder declarations for Darwin.
// Native unwinding is not implemented on macOS yet.

#pragma once

#ifdef __APPLE__

#    include <string>
#    include <vector>

#    include "mem.h"
#    include "native_frame.h"

// Note: This is included INSIDE namespace pystack {} in unwinder.h

class AbstractUnwinder
{
  public:
    virtual ~AbstractUnwinder() = default;

    virtual remote_addr_t
    getAddressforSymbol(const std::string& symbol, const std::string& modulename) const
    {
        (void)symbol;
        (void)modulename;
        return 0;
    }

    virtual std::vector<NativeFrame> unwindThread(pid_t tid) const = 0;

    static std::string demangleSymbol(const std::string& symbol)
    {
        return symbol;  // No demangling on Darwin stub
    }
};

#endif  // __APPLE__
