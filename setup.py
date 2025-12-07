import os
import pathlib
import sys
from sys import platform

try:
    import pkgconfig
except ImportError:
    pkgconfig = None

import setuptools
from Cython.Build import cythonize

IS_LINUX = "linux" in platform
IS_MACOS = "darwin" in platform

if not (IS_LINUX or IS_MACOS):
    raise RuntimeError(f"pystack does not support this platform ({platform})")


install_requires = []


TEST_BUILD = False
if "--test-build" in sys.argv:
    TEST_BUILD = True
    sys.argv.remove("--test-build")


if os.getenv("CYTHON_TEST_MACROS", None) is not None:
    TEST_BUILD = True


COMPILER_DIRECTIVES = {
    "language_level": 3,
    "embedsignature": True,
    "boundscheck": False,
    "wraparound": False,
    "cdivision": True,
    "c_string_type": "unicode",
    "c_string_encoding": "utf8",
    "freethreading_compatible": True,
}

DEFINE_MACROS = []

if TEST_BUILD:
    COMPILER_DIRECTIVES = {
        "language_level": 3,
        "boundscheck": True,
        "embedsignature": True,
        "wraparound": True,
        "cdivision": False,
        "profile": True,
        "linetrace": True,
        "overflowcheck": True,
        "infer_types": True,
        "c_string_type": "unicode",
        "c_string_encoding": "utf8",
        "freethreading_compatible": True,
    }
    DEFINE_MACROS.extend([("CYTHON_TRACE", "1"), ("CYTHON_TRACE_NOGIL", "1")])

library_flags = {"libraries": ["elf", "dw"]}

try:
    if IS_LINUX:
        library_flags = pkgconfig.parse("libelf libdw")
except EnvironmentError as e:

    print("pkg-config not found.", e)
    print("Falling back to static flags.")
except pkgconfig.PackageNotFoundError as e:
    print("Package Not Found", e)
    print("Falling back to static flags.")

if "define_macros" not in library_flags:
    library_flags["define_macros"] = []

library_flags["define_macros"].extend(DEFINE_MACROS)

PYSTACK_EXTENSION = setuptools.Extension(
    name="pystack._pystack",
    sources=[
        "src/pystack/_pystack.pyx",
        "src/pystack/_pystack/logging.cpp",
        "src/pystack/_pystack/mem.cpp",
        "src/pystack/_pystack/process.cpp",
        "src/pystack/_pystack/pycode.cpp",
        "src/pystack/_pystack/pyframe.cpp",
        "src/pystack/_pystack/pythread.cpp",
        "src/pystack/_pystack/pytypes.cpp",
        "src/pystack/_pystack/version.cpp",
    ],

    language="c++",
    extra_compile_args=["-std=c++17"],
    extra_link_args=["-std=c++17"],
    **library_flags,
)

if IS_LINUX:
    PYSTACK_EXTENSION.sources.extend([
        "src/pystack/_pystack/corefile.cpp",
        "src/pystack/_pystack/elf_common.cpp",
        "src/pystack/_pystack/unwinder.cpp",
        "src/pystack/_pystack/platform/linux/tracer.cpp",
        "src/pystack/_pystack/platform/linux/memory.cpp",
    ])
elif IS_MACOS:
    PYSTACK_EXTENSION.sources.extend([
        "src/pystack/_pystack/platform/darwin/tracer.cpp",
        "src/pystack/_pystack/platform/darwin/memory.cpp",
        "src/pystack/_pystack/unwinder.cpp",  # Included but guarded
    ])
    # Remove elf/dw libraries if they were added by default
    if "elf" in PYSTACK_EXTENSION.libraries:
        PYSTACK_EXTENSION.libraries.remove("elf")
    if "dw" in PYSTACK_EXTENSION.libraries:
        PYSTACK_EXTENSION.libraries.remove("dw")


if IS_LINUX:
    PYSTACK_EXTENSION.libraries.extend(["dl", "stdc++fs"])
else:
    PYSTACK_EXTENSION.libraries.extend(["dl"])



about = {}
with open("src/pystack/_version.py") as fp:
    exec(fp.read(), about)

HERE = pathlib.Path(__file__).parent.resolve()
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding="utf-8")

setuptools.setup(
    name="pystack",
    version=about["__version__"],
    python_requires=">=3.7.0",
    description="Analysis of the stack of remote python processes",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/bloomberg/pystack",
    author="Pablo Galindo Salgado",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development :: Debuggers",
    ],
    package_dir={"": "src"},
    packages=["pystack"],
    ext_modules=cythonize(
        [PYSTACK_EXTENSION],
        include_path=["src/pystack"],
        compiler_directives=COMPILER_DIRECTIVES,
    ),
    install_requires=install_requires,
    include_package_data=False,
    package_data={
        "pystack": [
            "pystack/*.pyi",
            "pystack/*.typed",
        ]
    },
    entry_points={
        "console_scripts": ["pystack=pystack.__main__:main"],
    },
)
