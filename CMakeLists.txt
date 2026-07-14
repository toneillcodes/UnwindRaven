cmake_minimum_required(VERSION 3.16)
project(UnwindRaven C)

# Require MSVC
if (NOT MSVC)
    message(FATAL_ERROR "UnwindRaven must be built with MSVC. It CAN be built with mingw (with the exception of the BlueprintCallstack tool), but MSVC is preferred for accuracy.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directory for all binaries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# MSVC compile flags
add_compile_options(
    /Zi        # PDB debug info
    /Z7        # (alternative) embed debug info in obj
    /Oy-       # disable frame pointer omission
    /FAs       # assembly listing
    /FAcs      # assembly + prolog/epilog
)

# MSVC link flags
add_link_options(
    /DEBUG     # generate .pdb
)

# Automatic symbol server configuration
set(SYM_PATH "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols")
add_definitions(-DSYMBOL_SERVER_PATH="${SYM_PATH}")

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

# Main tools
add_executable(UnwindRaven examples/UnwindRaven.c)
target_link_libraries(UnwindRaven unwindraven_core)

add_executable(UnwindRavenHellow examples/UnwindRaven-Hellow.c)
target_link_libraries(UnwindRavenHellow unwindraven_core)

# Blueprint callstack harvester (MSVC-only)
add_executable(BlueprintCallstack tools/blueprint-callstack.c)
target_link_libraries(BlueprintCallstack unwindraven_core)

# Copy correct dbghelp.dll automatically
add_custom_command(TARGET BlueprintCallstack POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/dbghelp.dll"
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbghelp.dll"
)