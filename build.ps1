# MSYS2 MinGW64 paths
$MsysRoot = "C:\msys64"
$Mingw64Bin = "$MsysRoot\mingw64\bin"

# Explicit tool paths
$CMake = "$Mingw64Bin\cmake.exe"
$Ninja = "$Mingw64Bin\ninja.exe"

# Verify tools
& $CMake --version
& $Ninja --version

# Create build directory
if (!(Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

# Configure
& $CMake -S . -B build `
    -G "Ninja" `
    -DCMAKE_MAKE_PROGRAM="$Ninja" `
    -DCMAKE_TOOLCHAIN_FILE="cmake/toolchain-mingw64.cmake"

# Build
& $CMake --build build --config Release
