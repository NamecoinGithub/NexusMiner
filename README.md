# NexusMiner

Mining software for Nexus supporting GPU, FPGA, prime, hash, pool and solo mining. 

## Windows Quickstart
Have an Nvidia GPU and a windows machine?  Start mining in 3 steps. 
1. Download NexusMiner.exe and miner.conf from the [latest release](https://github.com/Nexusoft/NexusMiner/releases). 
2. Edit miner.conf and add your Nexus wallet address
3. Run NexusMiner.exe

## FPGA Mining
FPGAs are the most efficient hardware for mining the Nexus Hash channel.  Blackminer users see [these instructions](docs/blackminer_instructions.md).  Other users see the list of supported [FPGA boards](docs/fpga_support.md). 

## GPU Mining
GPUs are the most efficient hardware for mining the Nexus Prime channel.  Supported GPUs are Nvidia GTX/RTX 10x0, 20x0, and 30x0 series, and Radeon RX6000 series.  Nvidia RTX 20x0 and 30x0 GPUs have the best performance.  Hash channel mining with Nvidia GPUs is also supported. 

## Pools
* [primepool.nexus.io](https://primepool.nexus.io)
* [hashpool.nexus.io](http://hashpool.nexus.io)  
Connect to either pool on port 50000

## Prime Pool
To use the prime pool, set the following address and port in miner.conf:
```
    "wallet_ip" : "primepool.nexus.io",
    "port" : 50000,
```

 ## miner.conf Configuration File

  Some important config options in miner.conf

  ```
    "wallet_ip"             // the ip the NXS wallet (solo mining) or ip address/dns name of Pool  
    "port"                  // port of the NXS wallet/node (default 8323 for solo Phase 2, 50000 for pools)
    "mining_mode"           // mine the HASH or PRIME channel  
    "pool"                  // Pool option group, if present then pool mining is active  
        "username"          // NXS address  
        "display_name"      // display_name for the pool website  
```

**Port Configuration:**
- **Solo Mining**: Default port is `8323` (connects to LLL-TAO's `miningport`)
- **Pool Mining**: Use pool's port (typically `50000`)

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
- **Authentication signatures**: Required for MINER_AUTH_RESPONSE (always enabled)
- **Optional block signatures**: Enhanced validation for block submissions (disabled by default)
- **Performance optimized**: Thread-safe with minimal overhead (~100-500 μs per signature)

To enable optional block signing, add to your config:
```json
{
    "enable_block_signing": true
}
```

See [docs/unified_falcon_signature_protocol.md](docs/unified_falcon_signature_protocol.md) for details.

**Alternative - Generate keys only:**
```bash
./NexusMiner --create-keys
```

Add the generated keys to your `miner.conf`. See [docs/falcon_authentication.md](docs/falcon_authentication.md) and [PHASE2_INTEGRATION.md](PHASE2_INTEGRATION.md) for detailed instructions.

**Important:** Falcon authentication is **required** for solo mining. Legacy authentication has been removed for security reasons.

## Multi-Core CPU Mining
For optimal multi-core mining performance, configure multiple CPU worker instances in `miner.conf`:

```json
{
  "workers": [
    {"worker": {"id": "cpu0", "mode": {"hardware": "cpu"}}},
    {"worker": {"id": "cpu1", "mode": {"hardware": "cpu"}}},
    {"worker": {"id": "cpu2", "mode": {"hardware": "cpu"}}},
    {"worker": {"id": "cpu3", "mode": {"hardware": "cpu"}}}
  ]
}
```

Each worker runs independently on a separate thread and processes different nonce ranges. CPU thread control options (threads per worker, affinity masking) are available in the configuration but planned for future implementation.
  
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
## Support
* [Nexus Miners](https://t.me/NexusMiners) on telegram.

