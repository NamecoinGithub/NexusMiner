# Simplified .config Files for NexusMiner

## Overview

NexusMiner now supports a simplified `.config` file format designed to streamline the configuration process while providing advanced controls for optimizing hardware performance. This format is future-proof and compatible with planned GUI tools.

## Key Features

- **Preset Templates**: Ready-to-use configurations for different user skill levels
- **GPU Power Controls**: Fine-tune power limits, clock offsets, and fan speeds
- **CPU Thread Management**: Control thread allocation, priority, and core affinity
- **Golden Ratio Optimization**: Automatic efficiency calculations for optimal performance-to-power ratio
- **Import/Export**: Full compatibility with legacy `.conf` files

## Quick Start

### Creating a Configuration

Use the CLI to generate a preset configuration:

```bash
# Create a beginner GPU config for HASH mining
./NexusMiner --create-config beginner hash gpu

# Create an advanced CPU config for PRIME mining
./NexusMiner --create-config advanced prime cpu

# Create an intermediate GPU config for PRIME mining
./NexusMiner --create-config intermediate prime gpu
```

### Preset Levels

| Preset | Power Profile | Target Users |
|--------|--------------|--------------|
| **beginner** | Efficiency (80% power) | New miners, safe defaults |
| **intermediate** | Balanced (90% power) | Experienced users seeking balance |
| **advanced** | Performance (100% power) | Expert miners, full optimization |

### Mining a Simplified Config

```bash
# Run miner with simplified config
./NexusMiner your_config.config
```

## Configuration Reference

### Root Fields

| Field | Type | Description |
|-------|------|-------------|
| `config_version` | string | Config format version (currently "2.0") |
| `preset` | string | Preset level: "beginner", "intermediate", "advanced", "custom" |
| `wallet_ip` | string | Wallet or pool IP/hostname |
| `port` | number | Connection port (8323 for solo, 50000 for pools) |
| `mining_mode` | string | "HASH" or "PRIME" |
| `power_profile` | string | Global power profile: "efficiency", "balanced", "performance" |
| `power_limit_percent` | number | Global power limit (50-100%) |
| `target_hashrate` | number | Target hashrate goal (0 = auto) |

### Pool Settings (Optional)

```json
"pool": {
    "address": "YOUR_NXS_ADDRESS",
    "display_name": "YOUR_DISPLAY_NAME"
}
```

### Worker Configuration

Each worker represents a mining device. Workers can be CPU, GPU, or FPGA.

#### GPU Worker

```json
{
    "id": "gpu0",
    "hardware": "gpu",
    "gpu": {
        "device": 0,
        "power_limit_percent": 90,
        "power_profile": "balanced",
        "core_clock_offset": 0,
        "memory_clock_offset": 0,
        "fan_speed": 0,
        "target_hashrate": 0,
        "target_power": 0
    }
}
```

| Field | Description |
|-------|-------------|
| `device` | GPU device index (0, 1, 2, ...) |
| `power_limit_percent` | GPU power limit (50-100%) |
| `power_profile` | Power profile for this GPU |
| `core_clock_offset` | Core clock adjustment in MHz |
| `memory_clock_offset` | Memory clock adjustment in MHz |
| `fan_speed` | Fan speed percentage (0 = auto) |
| `target_hashrate` | Target hashrate for this GPU (0 = auto) |
| `target_power` | Target power consumption in watts (0 = auto) |

#### CPU Worker

```json
{
    "id": "cpu0",
    "hardware": "cpu",
    "cpu": {
        "threads": 0,
        "affinity_mask": 0,
        "priority": 2,
        "power_limit_percent": 100,
        "hyperthreading": true,
        "efficiency_cores": false,
        "target_hashrate": 0
    }
}
```

| Field | Description |
|-------|-------------|
| `threads` | Number of threads (0 = auto-detect) |
| `affinity_mask` | CPU core affinity bitmask (0 = no affinity) |
| `priority` | Thread priority (0=low, 1=below_normal, 2=normal, 3=above_normal, 4=high) |
| `power_limit_percent` | CPU power limit (50-100%) |
| `hyperthreading` | Enable SMT/hyperthreading |
| `efficiency_cores` | Use efficiency cores on hybrid CPUs |
| `target_hashrate` | Target hashrate (0 = auto) |

#### FPGA Worker

```json
{
    "id": "fpga0",
    "hardware": "fpga",
    "serial_port": "/dev/ttyUSB0"
}
```

### Logging Settings

| Field | Type | Description |
|-------|------|-------------|
| `console_logging` | boolean | Enable console output |
| `file_logging` | boolean | Enable file logging |
| `log_file` | string | Log file path |
| `log_level` | number | 0=trace, 1=debug, 2=info, 3=warn, 4=error |
| `stats_interval` | number | Statistics print interval in seconds |

### Authentication (Solo Mining)

For solo mining, Falcon authentication is required:

```json
"falcon_pubkey": "YOUR_PUBLIC_KEY_HEX",
"falcon_privkey": "YOUR_PRIVATE_KEY_HEX",
"enable_block_signing": false
```

Generate keys with: `./NexusMiner --create-keys`

## Power Profiles

### Efficiency (Golden Ratio)

Optimized for best hash-per-watt ratio. Typically runs at 70-80% power with minimal performance impact.

- Power limit: 80%
- Thread priority: Below normal
- Recommended for: 24/7 mining, hot environments

### Balanced

Good balance between performance and efficiency.

- Power limit: 90%
- Thread priority: Normal
- Recommended for: General use

### Performance

Maximum performance, highest power consumption.

- Power limit: 100%
- Thread priority: High
- Recommended for: Dedicated mining rigs, pool mining

## Import/Export

### Import Legacy Config

Convert a legacy `.conf` file to simplified `.config`:

```bash
./NexusMiner --import-config miner.conf
# Creates: miner.config
```

### Export to Legacy Format

Convert simplified `.config` back to legacy `.conf`:

```bash
./NexusMiner --export-config my_mining.config
# Creates: my_mining.conf
```

## Example Configurations

### Beginner GPU Mining (HASH)

```json
{
    "config_version": "2.0",
    "preset": "beginner",
    "wallet_ip": "127.0.0.1",
    "port": 8323,
    "mining_mode": "HASH",
    "power_profile": "efficiency",
    "power_limit_percent": 80,
    "console_logging": true,
    "workers": [
        {
            "id": "gpu0",
            "hardware": "gpu",
            "gpu": {
                "device": 0,
                "power_limit_percent": 80,
                "power_profile": "efficiency"
            }
        }
    ]
}
```

### Advanced Multi-GPU Mining

```json
{
    "config_version": "2.0",
    "preset": "advanced",
    "wallet_ip": "127.0.0.1",
    "port": 8323,
    "mining_mode": "HASH",
    "power_profile": "performance",
    "workers": [
        {"id": "gpu0", "hardware": "gpu", "gpu": {"device": 0, "power_limit_percent": 100}},
        {"id": "gpu1", "hardware": "gpu", "gpu": {"device": 1, "power_limit_percent": 100}},
        {"id": "gpu2", "hardware": "gpu", "gpu": {"device": 2, "power_limit_percent": 100}}
    ]
}
```

### Pool Mining with CPU

```json
{
    "config_version": "2.0",
    "preset": "intermediate",
    "wallet_ip": "primepool.nexus.io",
    "port": 50000,
    "mining_mode": "PRIME",
    "pool": {
        "address": "YOUR_NXS_ADDRESS",
        "display_name": "MyCPUMiner"
    },
    "workers": [
        {"id": "cpu0", "hardware": "cpu", "cpu": {"threads": 4, "priority": 2}}
    ]
}
```

## Backward Compatibility

The simplified `.config` format works alongside existing `.conf` files:

- NexusMiner auto-detects file format based on `config_version` field
- Legacy `.conf` files continue to work without modification
- Use `--import-config` and `--export-config` for conversion
- All existing workflows remain functional

## GUI Integration (Future)

The `.config` format is designed for future GUI tools:

- JSON-based for easy parsing
- Hierarchical structure for form-based editing
- Validation rules built into the format
- Preset system for quick setup wizards

## Troubleshooting

### Config Validation

Check your config before running:

```bash
./NexusMiner -c your_config.config
```

### Common Issues

1. **FPGA not working with PRIME**: FPGA hardware only supports HASH mining
2. **Power limit below 50%**: Minimum power limit is 50%
3. **Missing falcon keys for solo**: Solo mining requires Falcon authentication
