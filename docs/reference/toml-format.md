# TOML Configuration Format (.config)

## Overview

NexusMiner now supports TOML-style `.config` files as a simpler, more readable alternative to JSON `.conf` files. The TOML format is easier to read and edit, with support for comments and a cleaner syntax.

## File Format Detection

- Files ending in `.config` are parsed as TOML
- Files ending in `.conf` are parsed as JSON (backward compatible)
- All existing `.conf` files continue to work without modification

## TOML Configuration Format

### Basic Structure

TOML uses sections (in brackets) and key-value pairs:

```toml
[section_name]
key = "value"
number = 123
boolean = true
```

### Supported Sections

#### [wallet]
Connection settings for your Nexus node:
```toml
[wallet]
ip = "127.0.0.1"                # Node IP address
port = 8323                     # Mining port (default: 8323)
failover_wallet_ip = ""         # (optional) Failover node IP — leave empty to disable
failover_port = 0               # (optional) Failover port — 0 = same as primary port
failover_max_retries = 5        # Switch to failover after this many consecutive primary failures
```

#### [network]
Network configuration:
```toml
[network]
local_ip = "0.0.0.0"          # Local bind address (0.0.0.0 = all interfaces)
keepalive_interval = 24        # Keepalive interval in hours (1-168)
```

#### [mining]
Mining configuration:
```toml
[mining]
channel = 1                    # 1 = Prime (CPU), 2 = Hash (GPU/FPGA)
genesis = "abc...xyz"          # 64-character genesis hash (from wallet)
reward_address = "8BMeG..."    # NXS account address for rewards
```

#### [workers]
Worker configuration:
```toml
[workers]
count = 8                      # Number of workers to create
```

#### [cpu]
CPU mining settings (for Prime channel):
```toml
[cpu]
threads = 1                    # Threads per worker (default: 1)
efficiency_cores = true        # Use E-cores on hybrid CPUs (default: true)
priority = 2                   # Thread priority: 0=low, 1=below_normal, 2=normal, 3=above_normal, 4=high
power_limit_percent = 100      # Power limit: 50-100% (default: 100)
hyperthreading = true          # Use hyperthreading/SMT (default: true)
target_hashrate = 0            # Target hashrate: 0=max (default: 0)
```

#### [gpu]
GPU mining settings (for Hash channel):
```toml
[gpu]
device = 0                     # GPU device index (default: 0)
```

#### [stats]
Statistics output configuration:
```toml
[stats]
mode = "console"               # Output mode: "console" or "file"
```

#### [logging]
Logging configuration:
```toml
[logging]
level = 2                      # 0=off, 1=error, 2=info, 3=debug
```

## Example Configurations

### Solo Prime Mining
```toml
# miner-solo-prime.config
[wallet]
ip = "127.0.0.1"
port = 8323

[mining]
channel = 1
genesis = "YOUR_GENESIS_HASH_HERE"
reward_address = "YOUR_NXS_ADDRESS_HERE"

[workers]
count = 8

[cpu]
threads = 1
efficiency_cores = true
priority = 2
power_limit_percent = 100
hyperthreading = true
target_hashrate = 0

[stats]
mode = "console"

[logging]
level = 2
```

### Solo Hash Mining
```toml
# miner-solo-hash.config
[wallet]
ip = "127.0.0.1"
port = 8323

[mining]
channel = 2
genesis = "YOUR_GENESIS_HASH_HERE"
reward_address = "YOUR_NXS_ADDRESS_HERE"

[workers]
count = 1

[gpu]
device = 0

[stats]
mode = "console"

[logging]
level = 2
```

## Getting Started

1. **Copy an example config:**
   ```bash
   cp miner-solo-prime.config miner.config
   ```

2. **Get your genesis hash:**
   - In your Nexus wallet, run: `system/get/info`
   - Copy the `genesis` value (64 hex characters)

3. **Get your reward address:**
   - In your Nexus wallet, run: `finance/list/accounts`
   - Copy the `address` value

4. **Edit the config:**
   ```toml
   [mining]
   genesis = "your_64_character_genesis_hash"
   reward_address = "your_nxs_account_address"
   ```

5. **Run the miner:**
   ```bash
   ./NexusMiner miner.config
   ```

## Features and Benefits

### TOML Advantages
- **Readable**: Clear section headers and key-value pairs
- **Comments**: Use `#` for documentation
- **Simple**: No need for quotes on numbers, no trailing commas
- **Type-safe**: Automatic type detection (strings, numbers, booleans)

### Backward Compatibility
- All existing `.conf` (JSON) files work unchanged
- No migration required
- Use whichever format you prefer

### Error Handling
- Invalid lines are warned but don't stop parsing
- Provides line numbers for errors
- Validates data ranges (e.g., keepalive_interval clamped to 1-168 hours)

## Advanced Options

### Remote Mining
```toml
[wallet]
ip = "192.168.1.100"      # Remote node IP
port = 8323

[network]
local_ip = "0.0.0.0"      # Bind to all interfaces
                          # For localhost: use 127.0.0.1
                          # Do NOT use "auto" for localhost/VPN (requires internet DNS)
```

### Multi-threaded Workers
```toml
[workers]
count = 4                 # 4 workers

[cpu]
threads = 2               # 2 threads each = 8 total threads
```

### Debug Logging
```toml
[logging]
level = 3                 # Maximum verbosity
```

## Comparison: JSON vs TOML

### JSON (.conf)
```json
{
    "version": 1,
    "wallet_ip": "127.0.0.1",
    "port": 8323,
    "mining_mode": "PRIME",
    "workers": [
        {"worker": {"id": "cpu0", "mode": {"hardware": "cpu", "threads": 1}}},
        {"worker": {"id": "cpu1", "mode": {"hardware": "cpu", "threads": 1}}}
    ]
}
```

### TOML (.config)
```toml
[wallet]
ip = "127.0.0.1"
port = 8323

[mining]
channel = 1

[workers]
count = 2

[cpu]
threads = 1
```

The TOML format is much simpler and easier to understand!

## Limitations

The TOML parser currently supports a subset of TOML features focused on mining configuration:
- Sections with `[section_name]`
- Key-value pairs with `key = value`
- Strings (quoted), integers, and booleans
- Comments with `#`

Most common mining configurations are supported including CPU power controls, GPU workers, and stats output.

**GPU Configuration**: The TOML `[gpu]` section supports single GPU configuration only. For advanced worker configurations (multiple GPUs with individual settings, custom affinity masks), use JSON `.conf` files.

## Reference Files

- `miner-solo-prime.config` - Prime mining example
- `miner-solo-hash.config` - Hash mining example  
- `MASTER-REFERENCE.config` - Complete reference with all options
- `miner.conf.example` - JSON format example (backward compatible)

## Support

For questions or issues:
1. Check `MASTER-REFERENCE.config` for complete documentation
2. See `example_configs/` for more examples
3. Refer to the README.md for general miner documentation
