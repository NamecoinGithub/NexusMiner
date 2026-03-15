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
2. Get your reward address: run `finance/list/accounts`, copy the `address` field
3. Generate Falcon keys: `./NexusMiner --create-keys`
   - Copy the pubkey and privkey hex output into the `[falcon]` section of your config
4. Replace `YOUR_GENESIS_HASH_HERE` and `YOUR_NXS_REWARD_ADDRESS_HERE` in your chosen config
5. Secure the file: `chmod 600 configs/your-config.config` (protects your private key)
6. Run: `./NexusMiner configs/your-config.config`

## Port Reference

| Port | Lane | Use |
|------|------|-----|
| 8323 | Stateless (16-bit opcodes) | Default Prime channel port |
| 8325 | Stateless (16-bit opcodes) | Default Hash channel port |
| 9326 | Stateless TLS (reserved)   | Future TLS prime port (node PORT_SSL — currently 0) |
| 8326 | Legacy TLS (reserved)      | Future TLS legacy port (node PORT_SSL — currently 0) |
