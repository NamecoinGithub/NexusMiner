# NexusMiner — Premade TOML Configurations

Copy the config that matches your hardware and channel, fill in your `genesis` hash and `reward_address`, then run:

```bash
./NexusMiner configs/your-config.config
```

## Quick Reference

| File | Channel | Hardware | Use Case |
|------|---------|----------|----------|
| `cpu-prime-solo.config` | Prime (1) | CPU | Standard CPU prime mining |
| `cpu-prime-performance.config` | Prime (1) | CPU | High-core-count / performance |
| `cpu-hash-solo.config` | Hash (2) | CPU | CPU hash mining (testing) |
| `gpu-hash-solo.config` | Hash (2) | GPU | Single GPU hash mining |
| `gpu-hash-performance.config` | Hash (2) | GPU | Performance-tuned single GPU |
| `gpu-prime-solo.config` | Prime (1) | GPU | GPU-accelerated prime (if supported) |
| `cpu-gpu-prime-hybrid.config` | Prime (1) | CPU+GPU | Hybrid mining rig |
| `cpu-gpu-hash-hybrid.config` | Hash (2) | CPU+GPU | Hybrid hash rig |
| `ssl-remote-prime.config` | Prime (1) | CPU | Remote node with TLS/SSL |
| `ssl-remote-hash.config` | Hash (2) | GPU | Remote node with TLS/SSL |
| `MASTER-REFERENCE.config` | — | — | All options documented |

## Setup Steps

1. Get your genesis hash: in your Nexus wallet run `system/get/info`, copy the `genesis` field (64 hex chars)
2. For `reward_address`, use the same 64-char genesis hash from step 1.
   (Advanced: supply a different genesis hash to route rewards to a separate Tritium sigchain.)
3. Generate Falcon keys: `./NexusMiner --create-keys`
   - Copy the pubkey and privkey hex output into the `[falcon]` section of your config
4. Replace `YOUR_GENESIS_HASH_HERE` in your chosen config for both `genesis` and `reward_address`
5. Secure the file: `chmod 600 configs/your-config.config` (protects your private key)
6. Run: `./NexusMiner configs/your-config.config`

## Port Reference

| Port | Lane | Use |
|------|------|-----|
| 8323 | Legacy (8-bit opcodes) | Legacy mining lane |
| 9323 | Stateless (16-bit opcodes) | Default stateless mining lane |
| 8325 | Legacy TLS (reserved) | Future TLS legacy port (node PORT_SSL — currently 0) |
| 9325 | Stateless TLS (reserved) | Future TLS stateless port (node PORT_SSL — currently 0) |
