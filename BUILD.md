# Building NexusMiner

This guide covers building NexusMiner on all supported platforms.

## Prerequisites

### Ubuntu/Debian

```bash
# Required for all builds
sudo apt-get update
sudo apt-get install -y build-essential cmake git libssl-dev

# Required for Prime mining
sudo apt-get install -y libboost-all-dev libgmp-dev

# Required for CUDA (Nvidia GPU mining)
# Install CUDA Toolkit from https://developer.nvidia.com/cuda-downloads
```

### Windows

* **OpenSSL**: Download and run [OpenSSL installer](https://slproweb.com/products/Win32OpenSSL.html)
* **MPIR** (required for WITH_PRIME): Download and build from [http://www.mpir.org/](http://www.mpir.org/). Copy gmp*.lib and mpir.lib to NexusMiner/libs
* **boost** (required for WITH_PRIME): Download from [https://www.boost.org/users/download/](https://www.boost.org/users/download/) and extract to C:\boost
* **Visual Studio** or **MinGW** with CMake

**Note:** Windows builds require MPIR instead of GMP for Prime mining. NOMINMAX and _CRT_SECURE_NO_WARNINGS are set automatically by the build system.

## Clone and Checkout

```bash
git clone https://github.com/NamecoinGithub/NexusMiner.git
cd NexusMiner
git checkout STATELESS-MINER-HEAD
mkdir build && cd build
```

**Note:** `STATELESS-MINER-HEAD` is the development branch with the latest stateless mining protocol features. For stable releases, check the [releases page](https://github.com/NamecoinGithub/NexusMiner/releases) and checkout a specific release tag instead (e.g., `git checkout v<version>`).

## Build Options

The following CMake options control which features are built:

| Option | Default | Description |
|--------|---------|-------------|
| `WITH_PRIME` | OFF | Prime mining (requires Boost + GMP/MPIR) |
| `WITH_GPU_CUDA` | OFF | Nvidia GPU mining (requires CUDA Toolkit) |
| `WITH_GPU_AMD` | OFF | AMD GPU mining (requires HIP + ROCm) |
| `STATIC_OPENSSL` | ON | Link OpenSSL statically |

## Build Commands

All builds use the same basic structure. From the `build` directory, run cmake with your desired options, then make:

### CPU Prime only
```bash
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PRIME=On .. && make -j$(nproc)
```

### Nvidia GPU + Prime
```bash
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On -DWITH_PRIME=On .. && make -j$(nproc)
```

### AMD GPU + Prime
```bash
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_AMD=On -DWITH_PRIME=On .. && make -j$(nproc)
```

### Hash channel only (no Prime, no GPU)
```bash
cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
```

## AMD GPU Build Notes

Prime mining with Radeon RX6000 series GPUs is supported on Linux. The [ROCm](https://rocmdocs.amd.com/en/latest/Installation_Guide/Installation_new.html) toolkit is required. ROCm uses a special version of clang whose path must be passed to cmake:

```bash
cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_AMD=On -DWITH_PRIME=On ..
make -j$(nproc)
```

### Arch Linux

When using Arch Linux, you may need to explicitly specify OpenSSL paths:

```bash
cmake -DOPENSSL_ROOT_DIR=/usr \
      -DOPENSSL_SSL_LIBRARY=/usr/lib/libssl.so \
      -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/libcrypto.so \
      -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_GPU_AMD=On \
      -DWITH_PRIME=On ..
```

## Requirements

* **CMake**: 3.21 or later
* **C++17 compiler**: GCC 7+, Clang 5+, or MSVC 2017+
* **OpenSSL**: 1.1.1 or 3.0+ (auto-detected)
* **CUDA Toolkit** (optional, for Nvidia GPU mining)
* **ROCm/HIP** (optional, for AMD GPU mining)
* **Boost** (optional, required for Prime mining)
* **GMP** (Linux) or **MPIR** (Windows) (optional, required for Prime mining)

## After Building

Before running `NexusMiner`, copy `miner.conf` to the build folder and edit it with your settings. See the [Configuration Reference](docs/reference/nexus.conf.md) for details on configuring the miner.

For Falcon authentication setup (required for solo mining), see the main [README.md](README.md) or run:
```bash
./NexusMiner --create-falcon-config
```
