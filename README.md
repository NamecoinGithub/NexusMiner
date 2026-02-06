# NexusMiner

Mining software for Nexus supporting GPU, FPGA, prime, hash, and solo mining with advanced power controls.

## 🔐 Falcon Post-Quantum Cryptography

NexusMiner now supports **Falcon-512/1024 dual version** post-quantum signatures with **Falcon-1024 as the default** for maximum quantum security.

### Quick Start with Falcon-1024

Generate your quantum-resistant keys:
```bash
./falcon-keygen
```

This creates `miner.conf` with:
- ✅ Falcon-1024 (256-bit quantum security, **DEFAULT**)
- ✅ Physical Falcon OFF (0 blockchain overhead)
- ✅ Ready to mine!

### Why Falcon-1024 Default?

| Feature | Falcon-512 | Falcon-1024 (Default) |
|---------|------------|----------------------|
| **Quantum Security** | 128-bit | **256-bit** |
| **Quantum Resistance** | Strong | **2^64× Stronger** |
| **Blockchain Overhead** | 0 bytes | 0 bytes |
| **Recommendation** | Secure | **Maximum Security** ✅ |

### Lazy Miner Economics

Our default configuration achieves **51% blockchain savings** over 100 years:
- 70% of miners use defaults → 0 blockchain bytes, maximum security
- Net result: ~19.9 GB vs ~51 GB (all-Falcon-512) = **61% savings!**

📖 **Full Guide:** [docs/current/authentication/falcon-integration.md](docs/current/authentication/falcon-integration.md)

---

## 📚 Documentation

**Quick Links:**
- **[Configuration Reference](docs/reference/nexus.conf.md)** - Complete guide to all config options
- **[Quick Start Examples](docs/reference/config-examples/)** - Ready-to-use config templates
- **[Stateless Mining Protocol](docs/current/mining-protocols/stateless-mining.md)** - Modern push protocol
- **[Push Notification System](docs/current/mining-protocols/push-notifications.md)** - Event-driven block notifications
- **[Architecture Diagrams](docs/diagrams/)** - Mermaid diagrams of protocol architecture
- **[Protocol Reference](docs/reference/opcodes-reference.md)** - LLP protocol opcodes
- **[Troubleshooting Guide](docs/current/troubleshooting.md)** - Common issues and solutions

### By Topic

**Authentication:**
- [Falcon Integration Guide](docs/current/authentication/falcon-integration.md) - Getting started with post-quantum security
- [Falcon Key Generation](docs/current/authentication/falcon-keygen-guide.md) - How to generate Falcon keys
- [Genesis-First Protocol](docs/current/authentication/genesis-first-protocol.md) - Genesis-based key derivation
- [Unified Falcon Protocol](docs/current/authentication/unified-falcon-protocol.md) - Disposable vs physical signatures
- [Falcon Handshake Cache](docs/current/authentication/falcon-handshake-cache.md) - Session management

**Mining Protocols:**
- [Stateless Mining Protocol](docs/current/mining-protocols/stateless-mining.md) - Modern push-notification protocol
- [Push Notifications](docs/current/mining-protocols/push-notifications.md) - GET_BLOCK/NEW_BLOCK implementation
- [Channel Management](docs/current/mining-protocols/channel-management.md) - Prime/Hash channel handling
- [Height Tracking](docs/current/mining-protocols/height-tracking.md) - Multi-channel height management
- [Template Read Feed](docs/current/mining-protocols/template-read-feed.md) - Template delivery system

**Security:**
- [Security Overview](docs/current/security/security-overview.md) - Overall security architecture
- [ChaCha20 Encryption](docs/current/security/chacha20-encryption.md) - Session encryption
- [Falcon Security](docs/current/security/falcon-security.md) - Post-quantum cryptography details
- [TLS/HTTPS Integration](docs/current/security/tls-https.md) - Secure remote mining
- [Mutual TLS](docs/current/security/mutual-tls.md) - Client certificate authentication

**Configuration:**
- [nexus.conf Reference](docs/reference/nexus.conf.md) - Comprehensive configuration documentation
- [TOML Format Guide](docs/reference/toml-format.md) - TOML configuration syntax
- [Opcodes Reference](docs/reference/opcodes-reference.md) - LLP protocol opcodes
- [Config Examples](docs/reference/config-examples/) - Ready-to-use configuration templates

**Troubleshooting:**
- [Troubleshooting Guide](docs/current/troubleshooting.md) - Common issues and solutions
- [Enhanced Diagnostics](docs/current/troubleshooting/enhanced-diagnostics.md) - Advanced debugging
- [Dynamic Port Detection](docs/current/troubleshooting/dynamic-port-detection.md) - Port configuration
- [Cross Validation Recovery](docs/current/troubleshooting/cross-validation-recovery.md) - Validation issues

**Upgrade Guides:**
- [Legacy to Stateless Migration](docs/upgrade-guides/legacy-to-stateless.md) - Upgrading to modern protocol
- [Legacy Features Removed](docs/upgrade-guides/legacy-features-removed.md) - Deprecated features

---

## Windows Quickstart
Have an Nvidia GPU and a windows machine?  Start mining in 3 steps. 
1. Download NexusMiner.exe and miner.conf from the [latest release](https://github.com/Nexusoft/NexusMiner/releases). 
2. Edit miner.conf and add your Falcon authentication keys
3. Run NexusMiner.exe

## FPGA Mining
FPGAs are the most efficient hardware for mining the Nexus Hash channel.  Blackminer users see [these instructions](docs/blackminer_instructions.md).  Other users see the list of supported [FPGA boards](docs/fpga_support.md). 

## GPU Mining
GPUs are the most efficient hardware for mining the Nexus Prime channel.  Supported GPUs are Nvidia GTX/RTX 10x0, 20x0, and 30x0 series, and Radeon RX6000 series.  Nvidia RTX 20x0 and 30x0 GPUs have the best performance.  Hash channel mining with Nvidia GPUs is also supported. 

 ## Configuration Formats

  NexusMiner supports two configuration formats:
  
  ### TOML Format (.config) - **NEW!** Easier and More Readable
  
  Simple, clean syntax perfect for most users:
  ```toml
  [wallet]
  ip = "127.0.0.1"
  port = 8323
  
  [mining]
  channel = 1                    # 1=Prime, 2=Hash
  genesis = "YOUR_GENESIS_HASH"
  reward_address = "YOUR_NXS_ADDRESS"
  
  [workers]
  count = 8
  ```
  
  **TOML Example Files:**
  - `docs/reference/config-examples/solo-mining-prime.conf` - Prime mining template
  - `docs/reference/config-examples/solo-mining-hash.conf` - Hash mining template
  - `docs/reference/config-examples/master-reference.config` - Complete TOML documentation
  - `docs/reference/config-examples/stateless-mining.conf` - Modern stateless protocol
  - See [docs/reference/toml-format.md](docs/reference/toml-format.md) for full guide
  
  ### JSON Format (.conf) - Traditional Format
  
  Full-featured format with advanced options:

  **Essential Configuration Options:**
  ```json
    "version": 1,                           // Config version (required)
    "wallet_ip": "127.0.0.1",              // Nexus node IP address
    "port": 8323,                          // Node miningport (default: 8323)
    "local_ip": "0.0.0.0",                 // Local bind IP (0.0.0.0 = all interfaces)
    "mining_mode": "PRIME",                // PRIME or HASH channel
    
    "miner_falcon_pubkey": "<YOUR_KEY>",   // Falcon public key (required)
    "miner_falcon_privkey": "<YOUR_KEY>",  // Falcon private key (required)
    "tritium_genesis": "<YOUR_GENESIS>",   // Tritium account genesis (optional)
```

**See Example Configs:**
- `docs/reference/config-examples/MASTER_simple.conf` - Quick start template
- `docs/reference/config-examples/MASTER_REFERENCE.conf` - Complete documentation of ALL options
- `docs/reference/config-examples/multi_gpu_hash.conf` - Multi-GPU with power controls
- `docs/reference/config-examples/threadripper_128core_prime.conf` - High-core-count CPU mining
- `docs/reference/config-examples/hybrid_cpu_gpu.conf` - Combined CPU+GPU mining
- `docs/reference/config-examples/remote_tls_mining.conf` - Secure remote mining

## GPU Power Controls

NexusMiner now supports comprehensive GPU power management in the unified config format:

```json
{
    "workers": [{
        "worker": {
            "id": "gpu0",
            "mode": {
                "hardware": "gpu",
                "device": 0,
                "power_limit_percent": 85,      // Power limit: 50-100% (default: 100)
                "core_clock_offset": 100,        // Core clock offset in MHz (default: 0)
                "memory_clock_offset": 200,      // Memory clock offset in MHz (default: 0)
                "fan_speed": 70,                 // Fan speed: 0=auto, 1-100 (default: 0)
                "target_hashrate": 0             // Target hashrate limit, 0=max (default: 0)
            }
        }
    }]
}
```

**GPU Power Control Options:**
- `power_limit_percent`: Reduce GPU power consumption (50-100%, default: 100)
- `core_clock_offset`: Adjust core clock in MHz (-500 to +500, default: 0)
- `memory_clock_offset`: Adjust memory clock in MHz (-1000 to +1000, default: 0)
- `fan_speed`: Set fan speed (0=auto, 1-100=%, default: 0 for auto)
- `target_hashrate`: Limit hashrate (0=maximum, default: 0)

**Example - Efficiency Mode (80% power, balanced clocks):**
```json
"power_limit_percent": 80,
"core_clock_offset": 0,
"memory_clock_offset": 0,
"fan_speed": 0
```

## CPU Power Controls

Advanced CPU mining options for optimization and power management:

```json
{
    "workers": [{
        "worker": {
            "id": "cpu0",
            "mode": {
                "hardware": "cpu",
                "threads": 1,                    // Threads per worker (default: 1)
                "affinity_mask": 0,              // CPU core affinity (default: 0)
                "priority": 3,                   // Thread priority 0-4 (default: 2)
                "power_limit_percent": 90,       // Power limit: 50-100% (default: 100)
                "hyperthreading": true,          // Use SMT/HT cores (default: true)
                "efficiency_cores": true,        // Use E-cores on hybrid CPUs (default: true)
                "target_hashrate": 0             // Target hashrate limit, 0=max (default: 0)
            }
        }
    }]
}
```

**CPU Power Control Options:**
- `priority`: Thread priority level
  - 0 = Low
  - 1 = Below normal
  - 2 = Normal (default)
  - 3 = Above normal
  - 4 = High
- `power_limit_percent`: CPU power limit (50-100%, default: 100)
- `hyperthreading`: Enable hyperthreading/SMT cores (default: true)
- `efficiency_cores`: Use efficiency cores on hybrid CPUs like Intel 12th+ gen (default: true)
- `target_hashrate`: Limit hashrate (0=maximum, default: 0)

**High-Core-Count Systems:**

For CPUs with many cores (Threadripper, EPYC), create multiple workers:
```json
"workers": [
    {"worker": {"id": "cpu0", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}},
    {"worker": {"id": "cpu1", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}},
    {"worker": {"id": "cpu2", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}}
    // ... up to 96+ workers
]
```

See `docs/reference/config-examples/threadripper_128core_prime.conf` for a complete 96-worker configuration.

## Command line option arguments
```
    <miner_config_file>  Default=miner.conf
    -c --check           run config file check before miner startup
    -v --version         Show NexusMiner version
    --create-keys        Generate Falcon miner keypair for authentication
    --create-falcon-config                Generate complete Falcon SOLO config file
    --create-falcon-config-with-privkey   Generate Falcon config with private key embedded (less secure)
```

  `./NexusMiner ../../myownminer.conf -c`

## Falcon Miner Authentication (SOLO Mode - REQUIRED)
NexusMiner requires quantum-resistant Falcon-based authentication for SOLO mining. This provides stateless, session-based authentication with enhanced security.

**Stateless Mining Features:**
- Quantum-resistant authentication using Falcon-512 signatures (mandatory)
- Direct MINER_AUTH_RESPONSE protocol (no challenge-response handshake)
- Stateless mining protocol (no GET_HEIGHT polling)
- Session-based authentication for efficient communication
- Connects to LLL-TAO's `miningport` (default 8323)

**Quick Start - Generate complete config for SOLO PRIME mining:**
```bash
./NexusMiner --create-falcon-config
```

This creates `falconminer.conf` ready for SOLO PRIME mining against a local LLL-TAO node on `127.0.0.1:8323`. The private key is printed to stdout (keep it safe!). Start mining with `./NexusMiner -c falconminer.conf`.

**Mining Protocol:**
SOLO mining uses stateless protocol: Direct Falcon auth (MINER_AUTH_RESPONSE) → GET_BLOCK → mine → SUBMIT_BLOCK (no GET_HEIGHT polling)

**Unified Hybrid Falcon Signature Protocol:**
NexusMiner includes an optimized signature wrapper for all Falcon-512 operations:
- **Disposable Falcon signatures**: ALWAYS ON - Required for session authentication (0 bytes blockchain overhead)
- **Physical Falcon signatures**: CONFIGURABLE - Optional blockchain-stored proof (adds 809-1577 bytes/block, OFF by default)
- **ChaCha20 encryption**: ALWAYS ON - Core security for all connections (SessionID protection, localhost miners)
- **Performance optimized**: Thread-safe with minimal overhead (~100-500 μs per signature)

Disposable Falcon is core protocol functionality and cannot be disabled. Physical Falcon signatures can be enabled via the `enable_physical_falcon()` API when needed for future blockchain integration.

See [docs/current/authentication/unified-falcon-protocol.md](docs/current/authentication/unified-falcon-protocol.md) for details.

**Enhanced Falcon Handshake and Cache Management:**
NexusMiner now supports enhanced handshake with adaptive cache management:
- **ChaCha20 Encryption**: Optional wrapping of Falcon Public Keys (auto-enabled for remote mining)
- **Tritium GenesisHash Binding**: Links mining rewards to specific Tritium accounts
- **Session Key Exchange**: Secure session establishment with LLL-TAO Node
- **Adaptive Keep-Alive**: Configurable ping frequency to maintain cache presence (default: 24 hours)

Configuration example:
```json
{
    "tritium_genesis": "<your_32_byte_genesis_hash_hex>",
    "keepalive_interval": 24,
    "enable_chacha20_wrapping": false
}
```

See [docs/current/authentication/falcon-handshake-cache.md](docs/current/authentication/falcon-handshake-cache.md) for complete documentation.

**TLS/HTTPS Integration for Secure Remote Mining:**
NexusMiner supports TLS/HTTPS encrypted connections for secure remote mining:
- **TLS 1.2/1.3**: Modern protocol versions only (no SSL v2/v3)
- **Strong Cipher Suites**: ChaCha20-Poly1305, AES-GCM with forward secrecy
- **Certificate Validation**: Full peer certificate verification
- **Auto-Detection**: Automatically enables for remote connections
- **Mutual TLS (mTLS)**: Client certificate authentication for maximum security

Configuration example:
```json
{
    "wallet_ip": "mining.pool.com",
    "enable_tls": true,
    "tls_verify_peer": true,
    "tls_ca_cert_path": "",
    "tls_server_name": ""
}
```

**Mutual TLS (Client Certificates):**
```json
{
    "enable_tls": true,
    "tls_client_cert_path": "/path/to/client-cert.pem",
    "tls_client_key_path": "/path/to/client-key.pem",
    "tls_client_key_password": "optional"
}
```

See [docs/current/security/tls-https.md](docs/current/security/tls-https.md) for TLS documentation and [docs/current/security/mutual-tls.md](docs/current/security/mutual-tls.md) for mTLS setup.

**Alternative - Generate keys only:**
```bash
./NexusMiner --create-keys
```

Add the generated keys to your `miner.conf`. See [docs/current/authentication/falcon-keygen-guide.md](docs/current/authentication/falcon-keygen-guide.md) and [docs/current/authentication/falcon-phase2-integration.md](docs/current/authentication/falcon-phase2-integration.md) for detailed instructions.

**Important:** Falcon authentication is **required** for solo mining. Legacy authentication has been removed for security reasons.

## Multi-Core CPU Mining

For optimal multi-core mining performance, configure multiple CPU worker instances with power controls:

```json
{
  "workers": [
    {"worker": {"id": "cpu0", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}},
    {"worker": {"id": "cpu1", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}},
    {"worker": {"id": "cpu2", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}},
    {"worker": {"id": "cpu3", "mode": {"hardware": "cpu", "priority": 3, "power_limit_percent": 90}}}
  ]
}
```

Each worker runs independently on a separate thread and processes different nonce ranges. See `docs/reference/config-examples/threadripper_128core_prime.conf` for high-core-count systems (96+ workers).

**Available CPU options:**
- `threads`: Threads per worker (default: 1, multi-threading planned for future)
- `affinity_mask`: CPU core affinity bitmask (default: 0, planned for future)
- `priority`: Thread priority 0-4 (0=low, 2=normal, 4=high, default: 2)
- `power_limit_percent`: CPU power limit 50-100% (default: 100)
- `hyperthreading`: Enable SMT/hyperthreading (default: true)
- `efficiency_cores`: Use E-cores on hybrid CPUs (default: true)
- `target_hashrate`: Limit hashrate, 0=max (default: 0)
  
## Solo Mining Wallet Setup
For solo mining use the latest wallet daemon release 5.0.5 or greater and ensure the wallet has been unlocked for mining.

```
    -llpallowip=<ip-port>   ex: -llpallowip=192.168.0.1:9325 
                            note: this is not needed if you mine to localhost (127.0.0.1). This is primarily used for a local-area-network setup

    -mining                 Ensure mining LLP servers are initialized.
```
## Building NexusMiner (Cmake) 
Optional cmake build options are
* `WITH_GPU_CUDA`       to enable Nvidia gpu mining. CUDA Toolkit required
* `WITH_GPU_AMD`        to enable AMD (Radeon) gpu mining (see below). 
* `WITH_PRIME`          to enable PRIME channel mining. GMP and boost required
Example commands to build NexusMiner for Nvidia GPUs: 
```
git clone https://github.com/Nexusoft/NexusMiner.git
cd NexusMiner
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_CUDA=On -DWITH_PRIME=On ..
make -j4
```
Before running `NexusMiner` copy miner.conf to the build folder and edit it with your settings.

## AMD GPU Build 
Prime mining with Radeon RX6000 series GPUs is supported on Linux systems.  The [Rocm](https://rocmdocs.amd.com/en/latest/Installation_Guide/Installation_new.html) toolkit is required. Rocm uses a special version of clang who's path must be passed to cmake. Example cmake command for Radeon support:  
`cmake -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ -DCMAKE_BUILD_TYPE=Release -DWITH_GPU_AMD=On -DWITH_PRIME=On ..`

When using Arch linux you may have to run a build using the following:
```
cmake -DOPENSSL_ROOT_DIR=/usr \
      -DOPENSSL_SSL_LIBRARY=/usr/lib/libssl.so \
      -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/libcrypto.so \
      -DCMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_GPU_AMD=On \
      -DWITH_PRIME=On ..
```

### Windows Build Dependencies
* OpenSSL: 
    * Download and run OpenSSL [installer](https://slproweb.com/products/Win32OpenSSL.html)
* [MPIR](http://www.mpir.org/) (required for WITH_PRIME):
    * Download and build.  Copy gmp*.lib and mpir.lib to NexusMiner/libs
* [boost](https://www.boost.org/users/download/) (required for WITH_PRIME):
    * Download and extract to C:\boost
### Ubuntu/Debian Dependencies
* OpenSSL:
    * `sudo apt-get install libssl-dev`
* gmp (required for WITH_PRIME):  
    * `sudo apt-get install libgmp-dev`
* boost (required for WITH_PRIME):
    * `sudo apt-get install libboost-all-dev`

## Legacy Features Removed

**Pool Mining Removed** - The Nexus Node IS the pool. Pool-specific code has been removed. Use solo mining mode to connect to nodes.

**Simplified Config System Removed** - The dual config system (`.conf` vs `.config`) caused confusion. All power controls are now unified in the `.conf` format.

See [docs/upgrade-guides/legacy-features-removed.md](docs/upgrade-guides/legacy-features-removed.md) for migration guide and details.

## Support
* [Nexus Miners](https://t.me/NexusMiners) on telegram.

