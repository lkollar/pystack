#Add macOS Support for PyStack - PoC Plan

## Objective
Add PoC macOS arm64 support for live process analysis with basic Python stack traces.

## Scope
- Platform: macOS arm64 only
- Mode: Live process (pystack remote <pid>)
- Features: Basic stack traces, thread enum, GIL status
- Deferred: Core dumps, native unwinding, locals, x86_64

## Architecture

Platform abstraction layer:
- LinuxPlatform (refactored existing)
- DarwinPlatform (new macOS)

## macOS APIs (all ship with SDK)

- Process attach: task_for_pid() (needs entitlement)
- Memory read: mach_vm_read_overwrite()
- Memory maps: mach_vm_region_recurse_64()
- Thread enum: task_threads()
- Exe path: proc_pidpath()
- Binary: Minimal custom Mach-O parser

No external deps required.

## Implementation Phases

Phase 0: Multi-Platform Abstraction Layer
- **Objective**: Decouple Linux-specific implementations from the core analysis engine to enable support for macOS, Windows, and other future platforms.
- **Architectural Goals**:
  - Define a strictly typed `PlatformProcess` interface in C++ (`src/pystack/_pystack/platform/api.h`).
  - Abstract memory access (remote read/write) into a `PlatformMemory` interface.
  - Abstract thread enumeration into a `PlatformTracer` interface.
  - Decouple ELF/binary parsing from proper memory map interfaces.
- **Implementation Steps**:
  - Create `src/pystack/_pystack/platform/` directory structure.
  - Move Linux-specific code (ptrace, procfs parsing, process_vm_readv) to `src/pystack/_pystack/platform/linux/`.
  - Introduce compile-time platform selection in build system (CMake/setup.py).
  - Refactor `maps.py` to support pluggable map map parsers (e.g., `/proc` vs Mach APIs).
- **Outcome**: The codebase compiles on macOS with stubbed interfaces, identifying exactly where platform-specific implementations must be injected.


Phase 1: Memory Access
- Create src/pystack/_pystack/platform/darwin_platform.cpp
- Implement mach_vm_read_overwrite() wrapper
- Add task_for_pid() with error handling
- Test basic memory reads

Phase 2: Thread Discovery
- Implement task_threads()
- Port thread ID extraction
- Implement mach_vm_region_recurse_64() for maps
- Find PyInterpreterState using existing strategies

Phase 3: Frame Walking
- Verify CPython offsets work on macOS
- Test frame walking (portable code)
- Implement GIL detection
- Handle macOS edge cases

Phase 4: Polish
- Error handling (SIP, permissions)
- Handle unsigned binary restrictions
- Basic macOS tests
- Update docs

Phase 5: Native Stack Unwinding (Post-PoC)
- Integrate LLVM libunwind API
- Implement dSYM discovery mechanism
- Parse Mach-O symbol tables
- Extract source locations from DWARF
- Best-effort inline frame detection
- Merge native/Python frames (reuse Linux algorithm)
- Graceful degradation for missing debug info
- Test with Python.org builds including dSYMs

## Entitlements

Recommended: Sign with debugger entitlement for full task_for_pid() access

## Critical Files

Modified:
- setup.py
- src/pystack/_pystack/mem.cpp
- src/pystack/_pystack/process.cpp
- src/pystack/maps.py
- src/pystack/_pystack.pyx

New:
- src/pystack/_pystack/platform/darwin_platform.h
- src/pystack/_pystack/platform/darwin_platform.cpp
- pystack.entitlements

Unchanged (portable):
- src/pystack/_pystack/cpython/*.h
- src/pystack/_pystack/pyframe.cpp
- src/pystack/_pystack/pythread.cpp
- src/pystack/_pystack/pytypes.cpp

## Native Stack Unwinding on macOS

### Background

Linux PyStack uses libdwfl (elfutils) for native unwinding with DWARF debug info. macOS has different unwinding infrastructure.

### macOS Unwinding Technologies

1. **Compact Unwind Format** (Primary)
   - Apple's space-efficient format in `__unwind_info` section
   - 8-byte descriptors vs verbose DWARF CFI
   - Handles 93.64% of frames
   - 6.36% need DWARF escape to `__eh_frame`

2. **DWARF CFI** (Fallback)
   - Available in `__eh_frame` section
   - Much smaller than Linux `.eh_frame`
   - Used for complex cases

3. **libunwind** (Built-in)
   - Ships with macOS (LLVM libunwind)
   - Different from Linux gnu libunwind
   - Compatible API, different implementation

### Implementation Options

**Option A: LLVM libunwind** (RECOMMENDED)
- Use macOS built-in `/usr/lib/libunwind.dylib`
- Parses both compact unwind and DWARF
- No external dependencies
- Native macOS integration
- API: `unw_getcontext()`, `unw_init_remote()`, `unw_step()`

**Option B: Custom DWARF Parser**
- Parse `__eh_frame` directly from Mach-O
- More portable, similar to Linux approach
- More implementation work
- Misses compact unwind optimization

### Native Unwinding Limitations on macOS

1. **dSYM Bundles** - Debug symbols separate
   - DWARF not in main binary (stripped for release)
   - Stored in `.dSYM` bundle directories
   - Must locate via Spotlight metadata or `mdfind`
   - Example: `Python.framework.dSYM`

2. **Compact Unwind** - Different format
   - Not DWARF-based for majority of frames
   - Need custom parser or rely on libunwind
   - Less detailed than full DWARF

3. **Inline Frame Detection** - Harder
   - Requires DWARF `.debug_info` section
   - Only in dSYM, not main binary
   - May be unavailable if dSYM not installed
   - Best-effort only

4. **System Libraries** - Stripped
   - macOS frameworks often lack symbols
   - Shows addresses instead of function names
   - Unless dSYM downloaded from Apple
   - Common for system Python frameworks

5. **Performance** - Additional overhead
   - dSYM lookup adds latency
   - Spotlight query or filesystem search
   - Likely slower than Linux inline DWARF

### Feature Parity Comparison

| Feature | Linux | macOS Feasibility | Notes |
|---------|-------|-------------------|-------|
| Native unwinding | ✅ libdwfl | ✅ libunwind | Built-in on macOS |
| Python/Native merge | ✅ Full | ✅ Full | Same algorithm works |
| Inline frames | ✅ DWARF scopes | ⚠️ Conditional | Only if dSYM available |
| Symbol resolution | ✅ .symtab | ⚠️ Conditional | dSYM or stripped |
| Source locations | ✅ DWARF | ⚠️ Conditional | Only if dSYM available |
| C++ demangling | ✅ __cxa_demangle | ✅ Full | Same API on macOS |
| Frame filtering | ✅ Full | ✅ Full | CPython symbols same |

### PoC Strategy for Native Unwinding

**Phase 1 PoC: DEFER native unwinding**
- Focus on Python-only stacks
- Reduces initial complexity
- Allows faster PoC delivery

**Phase 5 (Post-PoC): Add native unwinding**
Tasks:
- Integrate LLVM libunwind API
- Implement dSYM discovery (Spotlight or mdfind)
- Parse Mach-O for symbol tables
- Handle missing debug info gracefully
- Best-effort inline frame support
- Test with Python.org builds (include dSYMs)

**Graceful Degradation:**
- If dSYM missing: show function addresses only
- If no symbols: show "??" with module name
- Continue unwinding despite missing info

### dSYM Discovery Implementation

**Approaches:**

1. **Spotlight Metadata API** (Fastest)
```c
MDQueryRef query = MDQueryCreate(NULL, CFSTR("kMDItemKind == 'dSYM'"), NULL, NULL);
// Filter by bundle identifier or binary UUID
```

2. **mdfind command** (Simpler)
```bash
mdfind "kMDItemKind == 'dSYM' && kMDItemDisplayName == 'Python.framework.dSYM'"
```

3. **Standard paths** (Fallback)
- `/usr/local/lib/*.dSYM`
- `~/Library/Developer/Xcode/DerivedData/*/Build/Products/*/*.dSYM`
- Next to binary: `binary.dSYM`

### Native Frame Collection Flow (Post-PoC)

```
1. Get thread register context (mach_thread_get_state)
2. Initialize libunwind cursor (unw_init_remote)
3. Step through frames (unw_step)
4. For each frame:
   - Get PC (unw_get_reg UNW_REG_IP)
   - Resolve symbol (unw_get_proc_name)
   - Locate module (dladdr or Mach-O parsing)
   - Find dSYM for module
   - Extract source location from DWARF (if available)
   - Detect inline frames (dwarf_getscopes if dSYM present)
5. Merge with Python frames (same algorithm as Linux)
```

### Risks

- SIP blocks system processes (document limitation)
- Entitlement distribution (provide instructions)
- CPython offsets differ (test Python.org builds)
- Thread ID mapping (use 3.11+ native_thread_id)
- **dSYM availability** (may be missing for system Python or stripped builds)
- **Performance** (dSYM lookup adds overhead vs Linux inline debug info)
- **Inline frames** (limited without dSYM, partial feature vs Linux)

## Success Criteria

1. Attach to arbitrary Python process (macOS arm64)
2. Display threads with GIL holder
3. Show Python stacks with function/file/line
4. Works Python 3.9-3.13
5. Graceful errors (SIP, permissions)
6. Linux unchanged

## Open Questions

1. Self-signed cert OK for PoC or need dev cert?
2. Focus on Python.org builds or also Homebrew/pyenv?
3. How verbose should SIP/permission errors be?
