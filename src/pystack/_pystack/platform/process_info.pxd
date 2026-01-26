from posix.types cimport pid_t

from _pystack.mem cimport VirtualMap as CppVirtualMap
from libc.stdint cimport uintptr_t
from libcpp.memory cimport unique_ptr
from libcpp.string cimport string as cppstring
from libcpp.vector cimport vector


cdef extern from "platform/process_info.h" namespace "pystack":
    cdef cppclass AbstractProcessInfo:
        cppstring getExecutablePath(pid_t pid) except+
        cppstring getThreadName(pid_t pid, int tid) except+
        bint processExists(pid_t pid) except+
        vector[CppVirtualMap] getMemoryMaps(pid_t pid) except+

        @staticmethod
        unique_ptr[AbstractProcessInfo] create() except+


cdef extern from "platform/process_info_parser.h" namespace "pystack":
    vector[CppVirtualMap] parseProcMaps(const cppstring& content) except+
