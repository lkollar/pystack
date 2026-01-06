from libc.stdint cimport uintptr_t
from libcpp.memory cimport shared_ptr
from libcpp.optional cimport optional
from libcpp.string cimport string as cppstring
from libcpp.vector cimport vector


cdef extern from "analyzer.h" namespace "pystack":
    cdef cppclass ModuleInfo:
        cppstring name
        cppstring path
        uintptr_t load_address
        uintptr_t end_address
        optional[cppstring] build_id

    cdef cppclass AbstractAnalyzer:
        optional[uintptr_t] getSymbolAddress(const cppstring& symbol, const ModuleInfo& module) except+
        vector[ModuleInfo] getModules() except+
        optional[ModuleInfo] findModule(const cppstring& name) except+
        uintptr_t getModuleLoadPoint(const ModuleInfo& module) except+

    cdef cppclass AbstractProcessAnalyzer(AbstractAnalyzer):
        @staticmethod
        shared_ptr[AbstractProcessAnalyzer] create(int pid) except+

    cdef cppclass AbstractCoreFileAnalyzer(AbstractAnalyzer):
        @staticmethod
        shared_ptr[AbstractCoreFileAnalyzer] create(
            const cppstring& corefile,
            optional[cppstring] executable,
            optional[cppstring] lib_search_path,
        ) except+

        cppstring locateLibrary(const cppstring& lib) except+
        vector[cppstring] getMissingModules() except+
        int getPid() except+
