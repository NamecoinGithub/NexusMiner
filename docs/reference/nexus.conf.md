# NexusMiner Configuration Reference (nexus.conf)

Complete reference for all configuration options in NexusMiner.

## Table of Contents
1. [Configuration Formats](#configuration-formats)
2. [Connection Settings](#connection-settings)
3. [Authentication](#authentication)
4. [Mining Configuration](#mining-configuration)
5. [Worker Configuration](#worker-configuration)
6. [Hardware-Specific Settings](#hardware-specific-settings)
7. [Network Settings](#network-settings)
8. [Logging](#logging)
9. [Advanced Options](#advanced-options)
10. [Security Best Practices](#security-best-practices)

---

## Configuration Formats

NexusMiner supports two configuration formats:

### TOML Format (.config) - Recommended
Simpler, more readable format with comments support.
```toml
[wallet]
ip = "127.0.0.1"
port = 8323

[mining]
channel = 1
```

**Example Files:**
- `docs/reference/config-examples/master-reference.config` - Complete TOML documentation
- `docs/reference/config-examples/solo-mining-prime.conf` - Prime mining template
- `docs/reference/config-examples/solo-mining-hash.conf` - Hash mining template

See [docs/reference/toml-format.md](toml-format.md) for complete TOML guide.

### JSON Format (.conf) - Legacy
Traditional JSON format, backward compatible.
```json
{
    "wallet_ip": "127.0.0.1",
    "port": 8323,
    "mining_mode": "SOLO"
}
```

**Example Files:**
- `docs/reference/config-examples/MASTER_REFERENCE.conf` - Complete JSON documentation
- `docs/reference/config-examples/basic-example.conf` - Simple JSON template

---

## Connection Settings

### `wallet_ip` / `[wallet] ip`
**Type:** String  
**Default:** `"127.0.0.1"`  
**Description:** IP address of the Nexus node to connect to.

**Examples:**
```toml
# Local node
[wallet]
ip = "127.0.0.1"

# Remote node
[wallet]
ip = "192.168.1.100"
```

**Notes:**
- Use `127.0.0.1` for local node mining
- Use remote IP for network mining
- Ensure node is running and accessible

---

### `port` / `[wallet] port`
**Type:** Integer  
**Default:** `8323`  
**Valid Range:** 1-65535  
**Description:** Mining port on the Nexus node.

**Stateless Mining (Modern Protocol):**
- Port `8323`: Stateless mining protocol (modern nodes with LLL-TAO PR #170)
- Supports push notifications (GET_BLOCK/NEW_BLOCK)
- No polling required

**Legacy Mining:**
- Port `9323`: Legacy mining protocol (older nodes)
- Uses GET_ROUND polling

**Examples:**
```toml
# Modern stateless protocol
[wallet]
port = 8323

# Legacy protocol
[wallet]
port = 9323
```

**See:** [docs/current/mining-protocols/stateless-mining.md](../current/mining-protocols/stateless-mining.md) for protocol details.

---

## Authentication

### `miner_falcon_pubkey` / `[falcon] pubkey`
**Type:** String (Hex)  
**Length:** 897 bytes (Falcon-512) or 1793 bytes (Falcon-1024)  
**Description:** Falcon public key for miner authentication.

**Generation:**
```bash
# Generate Falcon-1024 keys (recommended)
./NexusMiner --create-keys

# Generate Falcon-512 keys
./falcon-keygen --falcon512 -o miner.conf
```

**Security:**
- ✅ Falcon-1024: 256-bit quantum security (recommended, default)
- ✅ Falcon-512: 128-bit quantum security
- ⚠️ Public key can be shared safely

**Example:**
```toml
[falcon]
pubkey = "0123456789abcdef..."  # 897 or 1793 bytes hex
```

**See:** [docs/current/authentication/falcon-keygen-guide.md](../current/authentication/falcon-keygen-guide.md)

---

### `miner_falcon_privkey` / `[falcon] privkey`
**Type:** String (Hex)  
**Length:** 2305 bytes (Falcon-512) or 4609 bytes (Falcon-1024)  
**Description:** Falcon private key for signing authentication.

**Security:**
- 🔴 **NEVER share your private key**
- 🔴 **NEVER commit to version control**
- 🔴 **Store in secure location**
- ✅ Use file permissions (chmod 600 on Linux)

**File Permissions:**
```bash
chmod 600 miner.conf
```

**Example:**
```toml
[falcon]
privkey = "fedcba9876543210..."  # 2305 or 4609 bytes hex
```

---

### `tritium_genesis` / `[mining] genesis`
**Type:** String (Hex)  
**Length:** 64 characters (32 bytes)  
**Description:** Genesis hash of your Nexus Tritium account.

**How to get:**
```bash
# In Nexus wallet console:
system/get/info

# Copy the "genesis" field value
```

**Purpose:**
- Links mining rewards to your Tritium account
- Required for solo mining
- Enables stateless mining protocol
- Used for ChaCha20 session key derivation

**Example:**
```toml
[mining]
genesis = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

**See:** [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)

---

## Mining Configuration

### `channel` / `[mining] channel`
**Type:** Integer  
**Values:** `1` (Prime) or `2` (Hash)  
**Description:** Mining channel selection.

**Channel Types:**
- **1 (Prime Channel):**
  - CPU mining
  - Proof-of-Work: Prime number discovery
  - Best for: Multi-core CPUs, servers
  
- **2 (Hash Channel):**
  - GPU/FPGA mining
  - Proof-of-Work: SK1024 hashing
  - Best for: GPUs, FPGAs

**Examples:**
```toml
# Prime mining (CPU)
[mining]
channel = 1

# Hash mining (GPU/FPGA)
[mining]
channel = 2
```

---

### `reward_address` / `[mining] reward_address`
**Type:** String  
**Description:** NXS account address to receive mining rewards.

**How to get:**
```bash
# In Nexus wallet:
finance/list/accounts

# Use any account address
```

**Example:**
```toml
[mining]
reward_address = "8BMeG7vqvRxPWNJ9fX77XEZZv3DxLTx9jXXpY2jPB4vJWdRABjU"
```

**Notes:**
- Must be a valid Tritium account address
- Can be different from genesis account
- Rewards sent here after successful block

---

### `mining_mode` (JSON only)
**Type:** String  
**Values:** `"PRIME"` or `"HASH"`  
**Description:** Mining channel selection (JSON format only).

**Example:**
```json
{
    "mining_mode": "PRIME"
}
```

**Note:** In TOML format, use `[mining] channel = 1` or `channel = 2` instead.

---

## Worker Configuration

### `count` / `[workers] count`
**Type:** Integer  
**Default:** 1  
**Valid Range:** 1-256  
**Description:** Number of mining workers to create.

**Recommendations:**

**CPU (Prime Channel):**
```toml
# Use number of physical cores
[workers]
count = 8  # For 8-core CPU

# High-core-count systems
[workers]
count = 96  # For Threadripper 128-core (leave some for OS)
```

**GPU (Hash Channel):**
```toml
# One worker per GPU
[workers]
count = 4  # For 4 GPUs
```

**Hybrid (CPU + GPU):**
```json
{
    "workers": [
        {
            "worker": {
                "id": "cpu0",
                "mode": {"hardware": "cpu"}
            }
        },
        {
            "worker": {
                "id": "gpu0",
                "mode": {"hardware": "gpu", "device": 0}
            }
        }
    ]
}
```

**Example Files:**
- `docs/reference/config-examples/threadripper_128core_prime.conf` - 96-worker CPU config
- `docs/reference/config-examples/hybrid_cpu_gpu.conf` - Hybrid config
- `docs/reference/config-examples/multi_gpu_hash.conf` - Multi-GPU config

---

### `[cpu] threads`
**Type:** Integer  
**Default:** 1  
**Description:** Number of threads per CPU worker.

**Recommendations:**
- **Single-threaded (1):** Best for most CPUs
- **Multi-threaded (2+):** Experimental, may reduce efficiency

**Example:**
```toml
[cpu]
threads = 1
```

---

### `[cpu] efficiency_cores`
**Type:** Boolean  
**Default:** `true`  
**Description:** Use efficiency (E) cores on hybrid CPUs (Intel 12th gen+).

**Recommendations:**
- **true:** Use all cores (P+E) - maximum hashrate
- **false:** Use only P-cores - better power efficiency

**Example:**
```toml
[cpu]
efficiency_cores = true
```

---

## Hardware-Specific Settings

### GPU Power Controls

#### `power_limit_percent`
**Type:** Integer  
**Valid Range:** 50-100  
**Default:** 100  
**Description:** GPU power limit as percentage of TDP.

**Example:**
```json
{
    "worker": {
        "mode": {
            "hardware": "gpu",
            "device": 0,
            "power_limit_percent": 80
        }
    }
}
```

**Impact:**
- 100%: Maximum performance, highest power consumption
- 80%: Good balance (20% less power, ~10% less hashrate)
- 50%: Minimum performance, lowest power consumption

---

#### `core_clock_offset`
**Type:** Integer  
**Valid Range:** -500 to +500 MHz  
**Default:** 0  
**Description:** GPU core clock offset in MHz.

**Examples:**
```json
"core_clock_offset": 100   // +100 MHz overclock
"core_clock_offset": -200  // -200 MHz underclock
```

---

#### `memory_clock_offset`
**Type:** Integer  
**Valid Range:** -1000 to +1000 MHz  
**Default:** 0  
**Description:** GPU memory clock offset in MHz.

**Examples:**
```json
"memory_clock_offset": 200   // +200 MHz memory OC
"memory_clock_offset": -500  // -500 MHz memory UC
```

---

#### `fan_speed`
**Type:** Integer  
**Valid Range:** 0 (auto) or 1-100%  
**Default:** 0 (auto)  
**Description:** Manual fan speed control.

**Examples:**
```json
"fan_speed": 0   // Auto (default)
"fan_speed": 70  // Fixed 70%
```

---

#### `target_hashrate`
**Type:** Integer  
**Default:** 0 (unlimited)  
**Description:** Target hashrate limit in H/s (0 = maximum).

---

### CPU Power Controls

#### `priority`
**Type:** Integer  
**Valid Range:** 0-4  
**Default:** 2  
**Description:** Thread priority level.

**Levels:**
- 0: Lowest
- 1: Below normal
- 2: Normal (default)
- 3: Above normal
- 4: Highest

**Example:**
```json
{
    "worker": {
        "mode": {
            "hardware": "cpu",
            "priority": 3
        }
    }
}
```

---

#### `power_limit_percent` (CPU)
**Type:** Integer  
**Valid Range:** 50-100  
**Default:** 100  
**Description:** CPU power limit as percentage.

---

#### `hyperthreading`
**Type:** Boolean  
**Default:** `true`  
**Description:** Enable/disable SMT (Simultaneous Multithreading).

**Example:**
```json
{
    "worker": {
        "mode": {
            "hardware": "cpu",
            "hyperthreading": true
        }
    }
}
```

---

## Network Settings

### `local_ip` / `[network] local_ip`
**Type:** String  
**Default:** `"0.0.0.0"`  
**Description:** Local IP address to bind to.

**Values:**
- `"0.0.0.0"`: Bind to all interfaces (recommended)
- `"127.0.0.1"`: Bind to localhost only
- Specific IP: Bind to specific interface

**Example:**
```toml
[network]
local_ip = "0.0.0.0"
```

---

### `keepalive_interval` / `[network] keepalive_interval`
**Type:** Integer  
**Default:** 24 hours  
**Valid Range:** 1-168 hours  
**Description:** Session keepalive ping interval.

**Recommendations:**
- 24 hours: Default (good for always-on miners)
- 12 hours: Summer/unstable connections
- 1 hour: Testing/development

**Example:**
```toml
[network]
keepalive_interval = 24
```

**See:** [docs/current/authentication/falcon-handshake-cache.md](../current/authentication/falcon-handshake-cache.md)

---

### TLS/SSL Settings

#### `enable_tls`
**Type:** Boolean  
**Default:** `false` (auto-enabled for remote connections)  
**Description:** Enable TLS/SSL encrypted connections.

**Example:**
```json
{
    "enable_tls": true,
    "tls_verify_peer": true
}
```

**See:** [docs/current/security/tls-https.md](../current/security/tls-https.md)

---

#### `tls_ca_cert_path`
**Type:** String  
**Default:** `""` (use system CA certificates)  
**Description:** Path to CA certificate bundle file.

---

#### `tls_verify_peer`
**Type:** Boolean  
**Default:** `true`  
**Description:** Verify peer TLS certificate.

⚠️ Only disable for testing! Production should always verify.

---

#### `tls_server_name`
**Type:** String  
**Default:** `""` (use wallet_ip)  
**Description:** Server Name Indication for TLS handshake.

---

### Mutual TLS (Client Certificates)

#### `tls_client_cert_path`
**Type:** String  
**Description:** Path to client certificate file (PEM format).

**Example:**
```json
{
    "tls_client_cert_path": "/path/to/client-cert.pem",
    "tls_client_key_path": "/path/to/client-key.pem"
}
```

**See:** [docs/current/security/mutual-tls.md](../current/security/mutual-tls.md)

---

#### `tls_client_key_path`
**Type:** String  
**Description:** Path to client private key file (PEM format).

---

#### `tls_client_key_password`
**Type:** String  
**Description:** Password for encrypted client key (optional).

---

## Logging

### `log_level` / `[logging] level`
**Type:** Integer  
**Valid Range:** 0-3  
**Default:** 2  
**Description:** Logging verbosity level.

**Levels:**
- **0:** Trace (extremely verbose)
- **1:** Debug (detailed debug information)
- **2:** Info (default, recommended)
- **3:** Warn (warnings only)
- **4:** Error (errors only)
- **5:** Critical (critical errors only)

**Example:**
```toml
[logging]
level = 2
```

**Note:** Higher numbers = less verbose. Level 2 (Info) is recommended for production.

---

## Advanced Options

### Stateless Mining Protocol

**Auto-Negotiation:**
- Miner automatically detects node capabilities
- Sends `MINER_READY` (0xD007) after authentication
- If node supports stateless: receives `GET_BLOCK` (0xD008) push
- If node doesn't support: falls back to legacy `GET_ROUND` polling

**Configuration:**
- No manual configuration needed
- Works with both modern and legacy nodes
- Automatic protocol selection

**Verification:**
```
[Solo Protocol] Attempting stateless protocol (MINER_READY 0xD007)
[Solo Protocol] ✅ Stateless protocol ACTIVE
[Solo Stateless] ✨ STATELESS_GET_BLOCK (0xD008) received!
```

**See:** [docs/current/mining-protocols/stateless-mining.md](../current/mining-protocols/stateless-mining.md)

---

### Physical Falcon Signatures

#### `enable_physical_falcon` / `[falcon] enable_block_signing`
**Type:** Boolean  
**Default:** `false`  
**Description:** Enable physical block signatures (stored on blockchain).

**Impact:**
- Adds ~809 bytes per block submission (Falcon-512)
- Adds ~1577 bytes per block submission (Falcon-1024)
- Provides emergency backup authentication
- OFF by default for zero blockchain overhead

**Example:**
```toml
[falcon]
enable_block_signing = false
```

**See:** [docs/current/authentication/unified-falcon-protocol.md](../current/authentication/unified-falcon-protocol.md)

---

### ChaCha20 Encryption

**Status:** ALWAYS ON (core protocol security)

ChaCha20-Poly1305 encryption is always enabled for:
- Session ID protection
- Falcon public key wrapping (for remote mining)
- Genesis-derived key agreement

**See:**
- [docs/current/security/chacha20-encryption.md](../current/security/chacha20-encryption.md)
- [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)

---

## Security Best Practices

### Private Key Protection

**DO:**
- ✅ Set file permissions to 600 (`chmod 600 miner.conf`)
- ✅ Store config files in secure location
- ✅ Use encrypted filesystem if possible
- ✅ Back up keys securely (offline storage)

**DON'T:**
- 🔴 Never commit private keys to version control
- 🔴 Never share private keys
- 🔴 Never send keys over unencrypted channels
- 🔴 Never store in publicly accessible locations

---

### Remote Mining

**TLS Recommended:**
```json
{
    "wallet_ip": "remote-node.example.com",
    "enable_tls": true,
    "tls_verify_peer": true
}
```

**Falcon Authentication:**
- Always use Falcon-1024 for remote mining
- Verify node authenticity
- Use ChaCha20 encryption for public key transmission

**See:** [docs/reference/config-examples/remote_tls_mining.conf](config-examples/remote_tls_mining.conf)

---

### File Permissions (Linux/macOS)

```bash
# Secure your config file
chmod 600 miner.conf

# Verify permissions
ls -l miner.conf
# Should show: -rw------- (owner read/write only)
```

---

## Example Configurations

See `docs/reference/config-examples/` for complete examples:

### TOML Examples
- `master-reference.config` - Complete TOML documentation
- `solo-mining-prime.conf` - CPU Prime mining
- `solo-mining-hash.conf` - GPU Hash mining

### JSON Examples
- `MASTER_REFERENCE.conf` - Complete JSON documentation
- `basic-example.conf` - Simple JSON template
- `hybrid_cpu_gpu.conf` - Combined CPU+GPU
- `multi_gpu_hash.conf` - Multi-GPU with power controls
- `threadripper_128core_prime.conf` - High-core-count CPU
- `remote_tls_mining.conf` - Secure remote mining

---

## Migration Guides

For upgrading from older versions:
- [docs/upgrade-guides/legacy-to-stateless.md](../upgrade-guides/legacy-to-stateless.md) - Protocol migration
- [docs/upgrade-guides/legacy-features-removed.md](../upgrade-guides/legacy-features-removed.md) - Deprecated features

---

## Protocol Reference

For opcode and packet format details:
- [docs/reference/opcodes-reference.md](opcodes-reference.md) - LLP protocol opcodes

---

## Troubleshooting

For common issues and solutions:
- [docs/current/troubleshooting/enhanced-diagnostics.md](../current/troubleshooting/enhanced-diagnostics.md)
- [docs/current/troubleshooting/dynamic-port-detection.md](../current/troubleshooting/dynamic-port-detection.md)
- [docs/current/troubleshooting/cross-validation-recovery.md](../current/troubleshooting/cross-validation-recovery.md)

---

**Last Updated:** January 2026  
**Version:** 1.5+  
**Protocol:** Stateless mining (LLL-TAO PR #170)

---

## Quick Start Checklist

1. ✅ Generate Falcon keys: `./NexusMiner --create-keys`
2. ✅ Get your genesis hash from Nexus wallet
3. ✅ Get your reward address from Nexus wallet
4. ✅ Configure `miner.conf` with your keys and addresses
5. ✅ Set mining channel (1=Prime, 2=Hash)
6. ✅ Configure worker count for your hardware
7. ✅ Set file permissions: `chmod 600 miner.conf`
8. ✅ Start mining: `./NexusMiner miner.conf`

**For detailed setup:** See README.md and [docs/current/authentication/falcon-integration.md](../current/authentication/falcon-integration.md)
