cmake_minimum_required(VERSION 3.16)
project(UnwindRaven C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Force console subsystem so MinGW uses main() instead of WinMain()
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--subsystem,console")

include_directories(${CMAKE_SOURCE_DIR}/include)

set(UNWINDRAVEN_CORE_SOURCES
    src/common.c
    src/stack_blueprint.c
    src/synthetic_stack.c
    src/pe_loader.c
    src/veh.c
    src/unwindraven_core.c
)

add_library(unwindraven_core STATIC ${UNWINDRAVEN_CORE_SOURCES})

target_link_libraries(unwindraven_core
    dbghelp
    psapi
    advapi32
    user32
    kernel32
)

add_executable(UnwindRavenHellow examples/UnwindRaven-Hellow.c)
target_link_libraries(UnwindRavenHellow unwindraven_core)

add_executable(UnwindRaven examples/UnwindRaven.c)
target_link_libraries(UnwindRaven unwindraven_core)