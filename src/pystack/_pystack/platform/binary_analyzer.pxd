from libc.stdint cimport uintptr_t
from libcpp cimport bool as cppbool
from libcpp.memory cimport unique_ptr
from libcpp.optional cimport optional
from libcpp.string cimport string as cppstring


cdef extern from "platform/binary_analyzer.h" namespace "pystack":
    cdef cppclass SectionInfo:
        cppstring name
        cppstring flags
        uintptr_t addr
        uintptr_t corrected_addr
        size_t offset
        size_t size

    cdef cppclass AbstractBinaryAnalyzer:
        optional[SectionInfo] findSection(const cppstring& name) except+
        cppstring getBuildId() except+

        # Static factory method
        @staticmethod
        unique_ptr[AbstractBinaryAnalyzer] create(const cppstring& path) except+
