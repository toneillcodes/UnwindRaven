# Paths
$CMake = "C:\msys64\mingw64\bin\cmake.exe"

# Verify tools
& $CMake --version

# Create build directory
if (!(Test-Path "build-msvc")) {
    New-Item -ItemType Directory -Path "build-msvc" | Out-Null
}

# Configure MSVC build
& $CMake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64

# Build all targets (Release)
& $CMake --build build-msvc --config Release

Write-Host "[+] Build complete. Binaries are in ./bin/"