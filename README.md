# NexusMiner

[![Build Status](https://github.com/NamecoinGithub/NexusMiner/workflows/Build%20and%20Test/badge.svg)](https://github.com/NamecoinGithub/NexusMiner/actions)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](COPYING)

High-performance mining software for Nexus blockchain supporting GPU, FPGA, CPU mining on both HASH and PRIME channels.

## ✨ Features

- 🖥️ **Multi-Hardware Support**: CPU, GPU (NVIDIA/AMD), and FPGA mining
- ⛏️ **Dual Channel Mining**: HASH and PRIME channel support
- 🌐 **Pool & Solo Mining**: Connect to pools or mine solo with your own wallet
- 🚀 **High Performance**: Optimized mining algorithms for maximum hash rate
- 📊 **Real-time Statistics**: Monitor your mining performance
- 🐳 **Docker Support**: Easy deployment with Docker containers

## 🚀 Quick Start

### Windows Users

1. Download `NexusMiner.exe` and `miner.conf` from the [latest release](https://github.com/Nexusoft/NexusMiner/releases)
2. Edit `miner.conf` and add your Nexus wallet address
3. Run `NexusMiner.exe`

### Linux Users - Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/NamecoinGithub/NexusMiner.git
cd NexusMiner

# Edit miner.conf with your wallet address
nano miner.conf

# Start mining with Docker
docker-compose up -d
```

### Linux Users - Building from Source

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libgmp-dev libboost-all-dev

# Clone and build
git clone https://github.com/NamecoinGithub/NexusMiner.git
cd NexusMiner
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Copy config and run
cp ../miner.conf .
./NexusMiner
```

## 📝 Configuration

### Basic Pool Mining Setup

Edit `miner.conf`:

```json
{
    "wallet_ip": "primepool.nexus.io",
    "port": 50000,
    "mining_mode": "HASH",
    "pool": {
        "username": "YOUR_NEXUS_WALLET_ADDRESS",
        "display_name": "my_miner"
    }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `wallet_ip` | Pool address or wallet IP | `127.0.0.1` |
| `port` | Pool or wallet port | `8325` |
| `mining_mode` | Mining channel: `HASH` or `PRIME` | `HASH` |
| `pool.username` | Your Nexus wallet address | - |
| `pool.display_name` | Display name on pool website | - |
| `log_level` | Logging verbosity (0-6) | `2` |

See `example_configs/` directory for more configuration examples.

## ⛏️ Mining Options

### Pool Mining (Recommended for Beginners)

**Prime Pool:**
```json
{
    "wallet_ip": "primepool.nexus.io",
    "port": 50000,
    "mining_mode": "PRIME"
}
```

**Hash Pool:**
```json
{
    "wallet_ip": "hashpool.nexus.io",
    "port": 50000,
    "mining_mode": "HASH"
}
```

### Solo Mining

For solo mining, run a Nexus wallet daemon (v5.0.5+) with mining enabled:

```bash
./nexus -mining -llpallowip=YOUR_MINER_IP:9325
```

Then configure `miner.conf`:
```json
{
    "wallet_ip": "127.0.0.1",
    "port": 9325,
    "mining_mode": "HASH"
}
```

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

## 💻 Supported Hardware

### GPUs
- **NVIDIA**: GTX/RTX 10x0, 20x0, 30x0 series (best performance on RTX 20x0/30x0)
- **AMD**: Radeon RX 6000 series (Linux only, requires ROCm)

### FPGAs
FPGAs offer the best efficiency for HASH channel mining.
- See [FPGA Support Documentation](docs/fpga_support.md) for supported boards
- Blackminer users: [Setup Instructions](docs/blackminer_instructions.md)

## 📊 Command Line Options

```bash
./NexusMiner [options] [config_file]

Options:
  -h, --help       Show help message
  -c, --check      Validate config file before starting
  -v, --version    Show NexusMiner version

Examples:
  ./NexusMiner                    # Use default miner.conf
  ./NexusMiner custom.conf        # Use custom config
  ./NexusMiner --check            # Validate miner.conf
```

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Build the image
docker build -t nexusminer .

# Run with your config
docker run -v $(pwd)/miner.conf:/app/miner.conf:ro nexusminer
```

### Docker Compose

```bash
# Edit miner.conf with your settings
nano miner.conf

# Start container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop container
docker-compose down
```

## 🔍 Troubleshooting

### Common Issues

**"Unable to read miner.conf"**
- Ensure `miner.conf` is in the same directory as NexusMiner executable
- Check file permissions
- Validate JSON syntax with `./NexusMiner --check`

**"Connection declined"**
- Verify pool address and port are correct
- Check your internet connection
- For solo mining, ensure wallet daemon is running with `-mining` flag

**"No worker created" (GPU mining)**
- Ensure you built with `WITH_GPU_CUDA` or `WITH_GPU_AMD`
- Check CUDA/ROCm installation
- Verify GPU drivers are up to date

### Getting Help

- 💬 [Telegram: Nexus Miners](https://t.me/NexusMiners)
- 🐛 [GitHub Issues](https://github.com/NamecoinGithub/NexusMiner/issues)

## 📜 License

NexusMiner is released under the [GNU General Public License v3.0](COPYING).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## 🔗 Links

- [Nexus Website](https://nexus.io/)
- [Prime Pool](https://primepool.nexus.io)
- [Hash Pool](https://hashpool.nexus.io)
- [Nexus Explorer](https://nexus.io/explorer)

---

**Happy Mining! ⛏️**
