# Troubleshooting Guide

This guide helps you resolve common issues with NexusMiner.

## Table of Contents
- [Configuration Issues](#configuration-issues)
- [Connection Issues](#connection-issues)
- [Build Issues](#build-issues)
- [GPU Issues](#gpu-issues)
- [Performance Issues](#performance-issues)

## Configuration Issues

### "Unable to read miner.conf"

**Cause:** Config file is missing or not in the correct location.

**Solution:**
1. Ensure `miner.conf` exists in the same directory as `NexusMiner` executable
2. Check file permissions: `chmod 644 miner.conf`
3. Validate JSON syntax: `./NexusMiner --check`

### "Mandatory fields errors"

**Cause:** Required configuration fields are missing.

**Solution:**
Ensure your config includes these required fields:
```json
{
    "version": 1,
    "wallet_ip": "...",
    "port": 50000,
    "mining_mode": "HASH"
}
```

### Invalid JSON Format

**Cause:** Syntax errors in configuration file.

**Solution:**
- Use a JSON validator (https://jsonlint.com/)
- Common mistakes:
  - Missing commas between fields
  - Trailing comma on last field
  - Using single quotes instead of double quotes
  - Missing closing braces

## Connection Issues

### "Connection declined" or "Connection refused"

**Pool Mining:**
1. Check pool address and port are correct
2. Verify internet connection
3. Try alternative pool address
4. Check firewall isn't blocking connections

**Solo Mining:**
1. Ensure wallet daemon is running
2. Wallet must be started with `-mining` flag
3. Unlock wallet for mining
4. For remote mining, add `-llpallowip=MINER_IP:PORT`

### "Connection timeout"

**Solution:**
- Increase `connection_retry_interval` in config
- Check network latency to pool
- Verify DNS resolution: `ping pooladdress.com`

## Build Issues

### "CMake version too old"

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install cmake

# Or download latest from https://cmake.org/download/
```

Required: CMake 3.25 or newer

### "Could not find OpenSSL"

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Arch Linux
sudo pacman -S openssl

# Fedora
sudo dnf install openssl-devel
```

### "Could not find GMP" (for PRIME mining)

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install libgmp-dev

# Arch Linux
sudo pacman -S gmp

# Fedora
sudo dnf install gmp-devel
```

### "Could not find Boost" (for PRIME mining)

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install libboost-all-dev

# Arch Linux
sudo pacman -S boost

# Fedora
sudo dnf install boost-devel
```

### CUDA Build Errors

**Solution:**
1. Install CUDA Toolkit: https://developer.nvidia.com/cuda-downloads
2. Add CUDA to PATH:
   ```bash
   export PATH=/usr/local/cuda/bin:$PATH
   export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
   ```
3. Rebuild:
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On ..
   ```

### ROCm Build Errors (AMD)

**Solution:**
1. Install ROCm: https://rocmdocs.amd.com/
2. Use ROCm compiler:
   ```bash
   cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
         -DCMAKE_BUILD_TYPE=Release \
         -DWITH_GPU_AMD=On \
         -DWITH_PRIME=On ..
   ```

## GPU Issues

### "No worker created" when GPU configured

**Cause:** NexusMiner wasn't built with GPU support.

**Solution:**
Rebuild with GPU flags:
```bash
# For NVIDIA
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On ..

# For AMD
cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
      -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_AMD=On ..
```

### GPU Not Detected

**NVIDIA:**
```bash
# Check GPU is visible
nvidia-smi

# Update drivers if needed
sudo ubuntu-drivers autoinstall
```

**AMD:**
```bash
# Check GPU is visible
rocm-smi

# Verify ROCm installation
/opt/rocm/bin/rocminfo
```

### Low Hash Rate

**Solutions:**
1. Update GPU drivers to latest version
2. Increase power limit (for NVIDIA):
   ```bash
   nvidia-smi -pl 250  # Set to appropriate wattage
   ```
3. Check GPU isn't thermal throttling:
   ```bash
   nvidia-smi -q -d TEMPERATURE
   ```
4. Close other GPU-intensive applications
5. Try different mining configurations

### CUDA Out of Memory

**Solution:**
- Reduce number of concurrent workers
- Close other GPU applications
- Use GPU with more VRAM

## Performance Issues

### High CPU Usage

**Cause:** Too many workers or intensive logging.

**Solutions:**
1. Reduce number of workers
2. Lower log level in config:
   ```json
   "log_level": 1
   ```
3. Disable file logging if not needed

### Miner Crashes

**Solutions:**
1. Check logs for error messages
2. Verify config file is valid
3. Update to latest version
4. Test with basic CPU-only config first
5. Check system memory isn't exhausted

### Statistics Not Updating

**Solution:**
Ensure `print_statistics_interval` is set in config:
```json
"print_statistics_interval": 10
```

## Getting More Help

If you're still experiencing issues:

1. **Check Logs:** Look in `miner.log` for detailed error messages
2. **Enable Debug Logging:**
   ```json
   "log_level": 6
   ```
3. **Join Telegram:** [Nexus Miners](https://t.me/NexusMiners)
4. **Open GitHub Issue:** Include:
   - Your config file (remove wallet address)
   - Error messages from logs
   - System information (OS, GPU, etc.)
   - Steps to reproduce the issue

## Useful Commands

```bash
# Check NexusMiner version
./NexusMiner --version

# Validate config
./NexusMiner --check

# View help
./NexusMiner --help

# Test with minimal config
./NexusMiner test.conf --check
```
