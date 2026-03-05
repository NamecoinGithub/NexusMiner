# NexusMiner

Solo mining software for [Nexus](https://nexus.io) — GPU, FPGA, CPU, and RISC-V supported, with Falcon-1024 post-quantum authentication and ChaCha20-Poly1305 session encryption.

---

## Quick Start

```bash
# 1. Clone and build (Linux, CPU prime mining)
git clone https://github.com/NamecoinGithub/NexusMiner.git
cd NexusMiner && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_PRIME=On .. && make -j$(nproc)

# 2. Generate Falcon-1024 keys and starter config
./NexusMiner --create-falcon-config

# 3. Edit the generated falconminer.conf (set wallet IP / genesis hash)

# 4. Verify config
./NexusMiner -c falconminer.conf

# 5. Mine!
./NexusMiner falconminer.conf
```

**Windows:** download `NexusMiner.exe` + `miner.conf` from the
[latest release](https://github.com/Nexusoft/NexusMiner/releases), add your
Falcon keys, and run.

**RISC-V cross-compile:**

```bash
cmake --preset riscv64-cross && cmake --build build-riscv -j$(nproc)
```

---

## Hardware Support

| Hardware | Channel | Status |
|----------|---------|--------|
| Nvidia GTX/RTX 10x0 – 30x0 | Prime & Hash | ✅ CUDA |
| AMD Radeon RX6000 | Prime | ✅ ROCm |
| Blackminer FPGA | Hash | ✅ |
| CPU (any x86-64, ARM64) | Prime | ✅ |
| RISC-V (RVV 1.0, rv64gcv\_zk) | Hash & Prime | ✅ |

See [docs/hardware/HARDWARE.md](docs/hardware/HARDWARE.md) for GPU power controls,
multi-core configs, Windows build steps, and FPGA board list.  
See [docs/riscv/RISCV-OVERVIEW.md](docs/riscv/RISCV-OVERVIEW.md) for RISC-V
extension map, performance tables, and ecosystem status.

---

## Security Summary

| Layer | Algorithm | Notes |
|-------|-----------|-------|
| Authentication | Falcon-1024 | 256-bit post-quantum, session disposable |
| Session encryption | ChaCha20-Poly1305 | Always-on, hardware-accelerated on RISC-V (Zbkb/Zbkc) and x86 (AES-NI) |
| Transport | TLS 1.2 / 1.3 | Auto-enabled for remote connections |
| Quantum resistance | Falcon-512 / 1024 | Falcon-1024 default (2× stronger) |

See [docs/current/security/security-overview.md](docs/current/security/security-overview.md).

---

## Documentation

| Category | Link | Description |
|----------|------|-------------|
| **Build** | [BUILD.md](BUILD.md) | All-platform build guide |
| **Hardware** | [docs/hardware/HARDWARE.md](docs/hardware/HARDWARE.md) | GPU/FPGA/CPU detail & power controls |
| **RISC-V** | [docs/riscv/RISCV-OVERVIEW.md](docs/riscv/RISCV-OVERVIEW.md) | RISC-V extensions, performance, ecosystem |
| **RISC-V Build** | [docs/riscv/BUILD-RISCV.md](docs/riscv/BUILD-RISCV.md) | Cross-compile & native build guide |
| **RISC-V Diagrams** | [docs/riscv/RISCV-DIAGRAMS.md](docs/riscv/RISCV-DIAGRAMS.md) | 12 Mermaid architecture diagrams |
| **Config reference** | [docs/reference/nexus.conf.md](docs/reference/nexus.conf.md) | All config options |
| **Authentication** | [docs/current/authentication/falcon-integration.md](docs/current/authentication/falcon-integration.md) | Falcon-1024 setup |
| **Security** | [docs/current/security/chacha20-encryption.md](docs/current/security/chacha20-encryption.md) | ChaCha20-Poly1305 details |
| **TLS** | [docs/current/security/tls-https.md](docs/current/security/tls-https.md) | Secure remote mining |
| **Stateless protocol** | [docs/current/mining-protocols/stateless-mining.md](docs/current/mining-protocols/stateless-mining.md) | Modern push-notification protocol |
| **Diagrams** | [docs/diagrams/](docs/diagrams/) | Mermaid architecture diagrams |
| **Troubleshooting** | [docs/current/troubleshooting.md](docs/current/troubleshooting.md) | Common issues & solutions |
| **Upgrade guide** | [docs/upgrade-guides/legacy-to-stateless.md](docs/upgrade-guides/legacy-to-stateless.md) | Legacy → stateless migration |
| **Full docs index** | [docs/README.md](docs/README.md) | Complete documentation index |

---

## Command-Line Options

```
./NexusMiner [config_file]         Default config: miner.conf
  -c --check                       Validate config before starting
  -v --version                     Print version
  --create-keys                    Generate Falcon keypair
  --create-falcon-config           Generate complete Falcon SOLO config
  --create-falcon-config-with-privkey  Generate config with embedded privkey
```

---

## Wallet Setup (Solo Mining)

Requires Nexus wallet daemon ≥ 5.0.5, unlocked for mining:

```
-mining                          Enable mining LLP servers
-llpallowip=192.168.0.1:9325    Allow LAN miner IP (not needed for localhost)
```

See [docs/PROTOCOL_LANES.md](docs/PROTOCOL_LANES.md) for port details
(stateless port 9323 / legacy port 8323).

---

## License

[MIT](COPYING)
