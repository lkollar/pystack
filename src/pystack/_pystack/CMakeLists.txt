cmake_minimum_required(VERSION 2.8)
project(_pystack)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PythonInterp 3.7 REQUIRED)
find_package(PythonLibs 3.7 REQUIRED)
IF(NOT PYTHONLIBS_FOUND OR NOT PYTHON_EXECUTABLE)
    MESSAGE(SEND_ERROR "You need Python to build Python binding")
ENDIF(NOT PYTHONLIBS_FOUND OR NOT PYTHON_EXECUTABLE)

set(PYSTACK_SOURCES
    logging.cpp
    mem.cpp
    process.cpp
    pycode.cpp
    pyframe.cpp
    pythread.cpp
    version.cpp
    pytypes.cpp
    unwinder.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND PYSTACK_SOURCES
        corefile.cpp
        elf_common.cpp
        platform/linux/tracer.cpp
        platform/linux/memory.cpp
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND PYSTACK_SOURCES
        platform/darwin/tracer.cpp
        platform/darwin/memory.cpp
    )
endif()

add_library(_pystack STATIC ${PYSTACK_SOURCES})

set_property(TARGET _pystack PROPERTY POSITION_INDEPENDENT_CODE ON)
include_directories("." "cpython" ${PYTHON_INCLUDE_DIRS})
