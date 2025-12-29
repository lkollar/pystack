from libc.stdint cimport uintptr_t
from libcpp.string cimport string as cppstring


cdef extern from "elf_common.h" namespace "pystack":
    cdef cppclass ProcessAnalyzer:
        ProcessAnalyzer(int pid) except+

    cdef cppclass CoreFileAnalyzer:
        CoreFileAnalyzer(cppstring filename) except+
        CoreFileAnalyzer(cppstring filename, cppstring executable) except+
        CoreFileAnalyzer(cppstring filename, cppstring executable, cppstring lib_search_path) except+
