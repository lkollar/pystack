from _pystack.analyzer cimport AbstractCoreFileAnalyzer
from _pystack.analyzer cimport AbstractProcessAnalyzer
from _pystack.mem cimport MemoryMapInformation
from _pystack.mem cimport VirtualMap
from _pystack.mem cimport remote_addr_t
from libc.stdint cimport uintptr_t
from libcpp.memory cimport shared_ptr
from libcpp.string cimport string as cppstring
from libcpp.utility cimport pair
from libcpp.vector cimport vector


cdef extern from "process.h" namespace "pystack::AbstractProcessManager":
    cdef enum InterpreterStatus:
        RUNNING
        FINALIZED
        UNKNOWN

cdef extern from "platform/abstract_tracer.h" namespace "pystack":
    cdef cppclass AbstractProcessTracer:
        @staticmethod
        shared_ptr[AbstractProcessTracer] create(int pid) except+

cdef extern from "process.h" namespace "pystack":

    cdef cppclass AbstractProcessManager:
        remote_addr_t scanBSS() except+
        remote_addr_t scanHeap() except+
        remote_addr_t scanAllAnonymousMaps() except+
        remote_addr_t findInterpreterStateFromDebugOffsets() except+
        remote_addr_t findInterpreterStateFromSymbols() except+
        remote_addr_t findInterpreterStateFromElfData() except+
        ssize_t copyMemoryFromProcess(remote_addr_t addr, ssize_t size, void *destination) except+
        vector[int] Tids() except+
        InterpreterStatus isInterpreterActive() except+
        pair[int, int] findPythonVersion()
        void setPythonVersion(pair[int, int] version) except +
        void setPythonVersionFromDebugOffsets() except +

    cdef cppclass ProcessManager(AbstractProcessManager):
        ProcessManager(int pid, shared_ptr[AbstractProcessTracer] tracer, shared_ptr[AbstractProcessAnalyzer] analyzer, vector[VirtualMap] memory_maps, MemoryMapInformation map_info) except+

    cdef cppclass CoreFileProcessManager(AbstractProcessManager):
        CoreFileProcessManager(int pid, shared_ptr[AbstractCoreFileAnalyzer] analyzer, vector[VirtualMap] memory_maps, MemoryMapInformation map_info) except+
