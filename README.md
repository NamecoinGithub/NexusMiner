# NexusMiner - Prime Mining Edition

[![Build Status](https://github.com/NamecoinGithub/NexusMiner/workflows/Build%20and%20Test/badge.svg)](https://github.com/NamecoinGithub/NexusMiner/actions)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](COPYING)

Production-ready Prime mining software for Nexus blockchain. Optimized for GPU mining with simple configuration.

## ✨ Key Features

- ⛏️ **Prime Channel Mining**: Optimized for PRIME channel (GPU recommended)
- 🔌 **Auto Port Detection**: Set port to 0 for automatic pool/solo port selection
- 🌐 **Pool & Solo Mining**: Simple configs for both mining modes
- 🖥️ **Multi-Hardware**: GPU (NVIDIA/AMD), CPU, and FPGA support
- 📊 **Real-time Statistics**: Monitor your mining performance
- 🚀 **Easy Setup**: Simple configuration files ready to use

## 🚀 Quick Start - Prime Pool Mining

### 1. Get NexusMiner

**Windows:** Download `NexusMiner.exe` from [releases](https://github.com/Nexusoft/NexusMiner/releases)

**Linux:** Build from source (see below)

### 2. Configure for Pool Mining

Use the included `prime-pool.conf`:

```json
{
    "version": 1,
    "wallet_ip": "primepool.nexus.io",
    "port": 50000,
    "mining_mode": "PRIME",
    "pool": {
        "username": "YOUR_NXS_ADDRESS_HERE",
        "display_name": "my_miner"
    }
}
```

**Or use auto-port detection** with `prime-pool-auto.conf` (port 0):

```json
{
    "wallet_ip": "primepool.nexus.io",
    "port": 0,
    "mining_mode": "PRIME",
    "pool": {
        "username": "YOUR_NXS_ADDRESS_HERE"
    }
}
```

When port is set to `0`, NexusMiner automatically selects:
- Port **50000** for pool mining
- Port **9325** for solo mining

### 3. Run the Miner

```bash
# Windows
NexusMiner.exe prime-pool.conf

# Linux
./NexusMiner prime-pool.conf
```

## 🏠 Solo Mining Setup

### 1. Start Your Nexus Wallet

```bash
./nexus -mining -llpallowip=YOUR_MINER_IP:9325
```

### 2. Configure Solo Mining

Use the included `prime-solo.conf`:

```json
{
    "version": 1,
    "wallet_ip": "127.0.0.1",
    "port": 9325,
    "mining_mode": "PRIME"
}
```

**Or use auto-port** with `prime-solo-auto.conf`:

```json
{
    "wallet_ip": "127.0.0.1",
    "port": 0,
    "mining_mode": "PRIME"
}
```

### 3. Run the Miner

```bash
./NexusMiner prime-solo.conf
```


## 🛠️ Building from Source (Linux)

### Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libgmp-dev libboost-all-dev
```

### Build for GPU Prime Mining

```bash
git clone https://github.com/NamecoinGithub/NexusMiner.git
cd NexusMiner
mkdir build && cd build

# For NVIDIA GPUs
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On -DWITH_PRIME=On ..

# For AMD GPUs
cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
      -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_AMD=On -DWITH_PRIME=On ..

make -j$(nproc)
```

### Quick Build with Presets

```bash
# NVIDIA + Prime
cmake --preset cuda-prime
cmake --build --preset cuda-prime

# AMD + Prime
cmake --preset amd-prime
cmake --build --preset amd-prime
```

## 📝 Configuration Files Included

| File | Purpose | Port |
|------|---------|------|
| `prime-pool.conf` | Pool mining with explicit port | 50000 |
| `prime-pool-auto.conf` | Pool mining with auto port | 0 → 50000 |
| `prime-solo.conf` | Solo mining with explicit port | 9325 |
| `prime-solo-auto.conf` | Solo mining with auto port | 0 → 9325 |

## 🔧 Configuration Options

### Required Settings

```json
{
    "version": 1,
    "wallet_ip": "primepool.nexus.io",
    "port": 0,
    "mining_mode": "PRIME"
}
```

### Pool Mining (add pool section)

```json
{
    "pool": {
        "username": "YOUR_NXS_ADDRESS",
        "display_name": "my_miner"
    }
}
```

### Worker Configuration

```json
{
    "workers": [
        {
            "worker": {
                "id": "gpu0",
                "mode": {
                    "hardware": "gpu",
                    "device": 0
                }
            }
        }
    ]
}
```

**Hardware options:**
- `"gpu"` - GPU mining (NVIDIA/AMD)
- `"cpu"` - CPU mining  
- `"fpga"` - FPGA mining

### Port Auto-Detection Feature

Set `"port": 0` for automatic port selection:
- **Pool mining**: Automatically uses port 50000
- **Solo mining**: Automatically uses port 9325

This eliminates configuration errors when switching between pool and solo mining.

## 💻 Supported Hardware

### GPUs (Recommended for Prime Mining)
- **NVIDIA**: GTX/RTX 10x0, 20x0, 30x0, 40x0 series
- **AMD**: Radeon RX 6000, 7000 series (Linux only)

### Other Hardware
- **CPU**: All modern CPUs (less efficient for Prime)
- **FPGA**: Custom FPGA boards (see docs)

## 🛠️ Building from Source

### Build Options

NexusMiner supports multiple build configurations using CMake presets:

```bash
# Basic build (CPU and FPGA only)
cmake --preset default
cmake --build --preset default

# With NVIDIA GPU support
cmake --preset cuda-prime
cmake --build --preset cuda-prime

# With AMD GPU support (Linux only)
cmake --preset amd-prime
cmake --build --preset amd-prime
```

### CMake Build Flags

- `WITH_GPU_CUDA` - Enable NVIDIA GPU mining (requires CUDA Toolkit)
- `WITH_GPU_AMD` - Enable AMD GPU mining (requires ROCm)
- `WITH_PRIME` - Enable PRIME channel mining (requires GMP and Boost)

### Platform-Specific Instructions

<details>
<summary><b>Ubuntu/Debian</b></summary>

```bash
# Install build dependencies
sudo apt-get install -y build-essential cmake libssl-dev

# For PRIME mining
sudo apt-get install -y libgmp-dev libboost-all-dev

# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PRIME=On ..
make -j$(nproc)
```
</details>

<details>
<summary><b>Windows</b></summary>

**Prerequisites:**
- Visual Studio 2019 or newer
- [CMake](https://cmake.org/download/) 3.25+
- [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
- [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) (for GPU mining)

For PRIME mining, you'll also need:
- [MPIR](http://www.mpir.org/) (copy `gmp*.lib` and `mpir.lib` to `NexusMiner/libs`)
- [Boost](https://www.boost.org/users/download/) (extract to `C:\boost`)

```cmd
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On -DWITH_PRIME=On ..
cmake --build . --config Release
```
</details>

<details>
<summary><b>AMD GPU (ROCm) on Linux</b></summary>

```bash
# Install ROCm (see: https://rocmdocs.amd.com/)
# Then build with ROCm clang
cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_GPU_AMD=On \
      -DWITH_PRIME=On ..
make -j$(nproc)
```
</details>


## 📊 Command Line Options

```bash
./NexusMiner [options] [config_file]

Options:
  -h, --help       Show help message
  -c, --check      Validate config file before starting
  -v, --version    Show NexusMiner version

Examples:
  ./NexusMiner prime-pool.conf        # Use pool config
  ./NexusMiner prime-solo.conf        # Use solo config  
  ./NexusMiner --check                # Validate default miner.conf
```

## 🔍 Troubleshooting

### "Connection declined"
- **Pool mining**: Check pool address and port are correct
- **Solo mining**: Ensure wallet daemon is running with `-mining` flag

### "No worker created"
- Build with GPU support: `-DWITH_GPU_CUDA=On` or `-DWITH_GPU_AMD=On`
- Ensure CUDA/ROCm drivers are installed

### Low hash rate
- Update GPU drivers
- Check GPU isn't thermal throttling
- Try different worker configurations

**More help**: See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## 🔗 Resources

- 🌐 [Nexus Website](https://nexus.io/)
- ⛏️ [Prime Pool](https://primepool.nexus.io)
- 💬 [Telegram: Nexus Miners](https://t.me/NexusMiners)
- 📖 [Full Documentation](docs/)

## 📜 License

GNU General Public License v3.0 - See [COPYING](COPYING)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

**Happy Prime Mining! ⛏️💎**
