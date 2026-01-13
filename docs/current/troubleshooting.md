# NexusMiner Troubleshooting Guide

Common issues and solutions for NexusMiner configuration, mining, and connectivity.

## Table of Contents

1. [Connection Issues](#connection-issues)
2. [Authentication Problems](#authentication-problems)
3. [Mining Issues](#mining-issues)
4. [Performance Problems](#performance-problems)
5. [Configuration Errors](#configuration-errors)
6. [Hardware Issues](#hardware-issues)
7. [Advanced Diagnostics](#advanced-diagnostics)

---

## Connection Issues

### "Connection refused" or "Cannot connect to node"

**Symptoms:**
```
[Network] Failed to connect to 127.0.0.1:8323
[Network] Connection refused
```

**Solutions:**

1. **Check node is running:**
   ```bash
   ps aux | grep nexus
   # or
   systemctl status nexus
   ```

2. **Verify node mining is enabled:**
   ```ini
   # In nexus.conf:
   mining=1
   miningport=8323
   ```

3. **Check firewall rules:**
   ```bash
   # Linux
   sudo ufw status
   sudo ufw allow 8323/tcp
   
   # Check if port is listening
   netstat -tuln | grep 8323
   ```

4. **Verify correct IP/port in miner.conf:**
   ```toml
   [wallet]
   ip = "127.0.0.1"  # Use correct node IP
   port = 8323       # Use correct port
   ```

---

### "Connection timeout"

**Symptoms:**
```
[Network] Connection timeout after 30 seconds
```

**Solutions:**

1. **Check network connectivity:**
   ```bash
   ping <node_ip>
   telnet <node_ip> 8323
   ```

2. **Increase timeout (if high latency):**
   ```json
   {
       "connection_timeout": 60
   }
   ```

3. **Check for network restrictions:**
   - VPN/proxy interfering
   - ISP blocking ports
   - Router NAT configuration

---

### "Node doesn't support stateless protocol"

**Symptoms:**
```
[Solo Protocol] Attempting stateless protocol (MINER_READY 0xD007)
[Solo Protocol] ⚠️  No response - node doesn't support stateless
[Solo Protocol] ℹ️  Falling back to legacy GET_ROUND polling
```

**This is normal!** The miner automatically falls back to legacy protocol.

**To enable stateless:**
1. Update node to LLL-TAO 5.1.0+ with PR #170
2. Restart node with `mining=1` in nexus.conf
3. Restart miner (will auto-detect)

**See:** [docs/upgrade-guides/legacy-to-stateless.md](../upgrade-guides/legacy-to-stateless.md)

---

## Authentication Problems

### "Authentication failed"

**Symptoms:**
```
[Falcon Auth] ❌ Authentication failed
[Falcon Auth]    Reason: Invalid signature
```

**Solutions:**

1. **Verify Falcon keys are correct:**
   ```bash
   # Generate new keys
   ./NexusMiner --create-keys
   
   # Copy output to miner.conf
   ```

2. **Check genesis hash:**
   ```bash
   # In Nexus wallet console:
   system/get/info
   # Copy "genesis" field (32 bytes hex = 64 chars)
   ```

3. **Ensure keys match:**
   - Public key and private key must be from same keypair
   - Don't mix Falcon-512 and Falcon-1024 keys

4. **Check node whitelist (if enabled):**
   ```ini
   # In nexus.conf:
   # minerallowkey=<your_falcon_pubkey_hex>
   ```

---

### "No genesis - ChaCha20 encryption unavailable"

**Symptoms:**
```
[Falcon Auth] ⚠️  No genesis - ChaCha20 encryption unavailable
```

**Solution:**

Add genesis hash to miner.conf:

```toml
[mining]
genesis = "your_32_byte_genesis_hash_hex"
```

Get genesis from wallet:
```bash
# In Nexus wallet:
system/get/info
# Copy "genesis" field
```

**See:** [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)

---

### "Invalid Falcon key length"

**Symptoms:**
```
[Config] Error: Falcon public key must be 897 or 1793 bytes (hex)
```

**Solutions:**

1. **Check key format:**
   - Falcon-512: 897 bytes = 1794 hex characters
   - Falcon-1024: 1793 bytes = 3586 hex characters
   - Must be hex encoded (0-9, a-f)

2. **Regenerate keys:**
   ```bash
   ./NexusMiner --create-keys
   ```

3. **Verify no extra spaces/newlines:**
   ```bash
   # Remove whitespace
   echo -n "YOUR_KEY_HERE" | wc -c
   ```

---

## Mining Issues

### "No work received"

**Symptoms:**
```
[Mining] Waiting for work...
[Mining] No work received after 60 seconds
```

**Solutions:**

1. **Check node is synced:**
   ```bash
   # In Nexus wallet:
   system/get/info
   # Verify "blocks" matches network height
   ```

2. **Verify mining channel:**
   ```toml
   [mining]
   channel = 1  # 1=Prime, 2=Hash
   ```

3. **Check node has mining enabled:**
   ```ini
   # In nexus.conf:
   mining=1
   ```

4. **Enable debug logging:**
   ```toml
   [logging]
   level = 1  # Debug level
   ```

---

### "All blocks rejected - stale"

**Symptoms:**
```
[Mining] Block found!
[Submit] ❌ Block rejected: stale
```

**Solutions:**

1. **Check system time:**
   ```bash
   # Sync system clock
   sudo ntpdate pool.ntp.org
   # or
   sudo systemctl start systemd-timesyncd
   ```

2. **Reduce stale work:**
   - Update to stateless protocol (instant updates)
   - Reduce polling interval (if using legacy)
   - Improve network latency to node

3. **Check node connectivity:**
   - High latency to node
   - Packet loss
   - Node overloaded

---

### "Low hash rate"

**Symptoms:**
- Hash rate lower than expected
- GPU/CPU not fully utilized

**Solutions:**

1. **Check worker count:**
   ```toml
   [workers]
   count = 8  # Adjust for your hardware
   ```

2. **Verify hardware settings:**
   
   **CPU:**
   ```toml
   [cpu]
   threads = 1
   efficiency_cores = true
   ```
   
   **GPU:**
   ```json
   {
       "worker": {
           "mode": {
               "power_limit_percent": 100,
               "core_clock_offset": 0
           }
       }
   }
   ```

3. **Check system resources:**
   ```bash
   # CPU usage
   top
   htop
   
   # GPU usage
   nvidia-smi  # Nvidia
   radeontop   # AMD
   ```

4. **Disable power saving:**
   - Set CPU governor to "performance"
   - Disable GPU power management
   - Check BIOS settings

---

## Performance Problems

### "High CPU usage"

**Symptoms:**
- Miner using 100% CPU unexpectedly
- System slow/unresponsive

**Solutions:**

1. **Adjust worker count:**
   ```toml
   [workers]
   count = 6  # Leave some cores for OS
   ```

2. **Lower thread priority:**
   ```json
   {
       "worker": {
           "mode": {
               "priority": 1  # Below normal (0-4)
           }
       }
   }
   ```

3. **Check for polling loop:**
   - Legacy protocol polls continuously
   - Update to stateless protocol for event-driven mining

---

### "High memory usage"

**Symptoms:**
- Miner using excessive RAM
- System swapping

**Solutions:**

1. **Reduce worker count:**
   ```toml
   [workers]
   count = 4  # Fewer workers = less memory
   ```

2. **Check for memory leaks:**
   ```bash
   # Monitor memory over time
   watch -n 1 "ps aux | grep NexusMiner"
   ```

3. **Update to latest version:**
   - Memory leaks fixed in recent versions
   - Check GitHub releases

---

### "Network traffic too high"

**Symptoms:**
- Excessive bandwidth usage
- ISP throttling

**Solutions:**

1. **Use stateless protocol:**
   - 95% reduction in network traffic
   - Update miner and node

2. **Reduce polling (if legacy):**
   ```json
   {
       "poll_interval": 5000  # 5 seconds (milliseconds)
   }
   ```

3. **Monitor traffic:**
   ```bash
   # Linux
   iftop
   nethogs
   ```

---

## Configuration Errors

### "Failed to parse config file"

**Symptoms:**
```
[Config] Error parsing miner.conf: Invalid TOML syntax
```

**Solutions:**

1. **Check TOML syntax:**
   ```toml
   # Correct
   [section]
   key = "value"
   
   # Wrong
   [section
   key = value  # Missing quotes
   ```

2. **Validate TOML:**
   ```bash
   # Online validator: https://www.toml-lint.com/
   ```

3. **Check JSON syntax:**
   ```json
   {
       "key": "value"  // No trailing comma on last item
   }
   ```

4. **Use config validation:**
   ```bash
   ./NexusMiner -c miner.conf
   ```

---

### "Missing required field"

**Symptoms:**
```
[Config] Error: Missing required field 'falcon.pubkey'
```

**Solutions:**

1. **Check all required fields:**
   ```toml
   [falcon]
   pubkey = "..."
   privkey = "..."
   
   [mining]
   genesis = "..."
   reward_address = "..."
   channel = 1
   ```

2. **Use example config:**
   ```bash
   cp docs/reference/config-examples/stateless-mining.conf miner.conf
   # Edit with your values
   ```

---

### "Config file not found"

**Symptoms:**
```
[Config] Error: Could not open miner.conf
```

**Solutions:**

1. **Specify full path:**
   ```bash
   ./NexusMiner /full/path/to/miner.conf
   ```

2. **Check file permissions:**
   ```bash
   ls -l miner.conf
   chmod 600 miner.conf
   ```

3. **Create default config:**
   ```bash
   ./NexusMiner --create-falcon-config
   ```

---

## Hardware Issues

### GPU Not Detected

**Symptoms:**
```
[GPU] No CUDA devices found
[GPU] No AMD devices found
```

**Solutions:**

1. **Check GPU drivers:**
   ```bash
   # Nvidia
   nvidia-smi
   
   # AMD
   rocm-smi
   ```

2. **Verify build options:**
   ```bash
   # Rebuild with GPU support
   cmake -DWITH_GPU_CUDA=On ..  # Nvidia
   cmake -DWITH_GPU_AMD=On ..   # AMD
   ```

3. **Check GPU visibility:**
   ```bash
   lspci | grep -i nvidia
   lspci | grep -i amd
   ```

---

### GPU Crashes / Instability

**Symptoms:**
- Miner crashes during mining
- GPU driver resets
- System freezes

**Solutions:**

1. **Reduce overclock:**
   ```json
   {
       "core_clock_offset": 0,      // Remove overclock
       "memory_clock_offset": 0
   }
   ```

2. **Lower power limit:**
   ```json
   {
       "power_limit_percent": 80    // Reduce from 100%
   }
   ```

3. **Check temperatures:**
   ```bash
   nvidia-smi
   # If temp > 80°C, increase fan speed or improve cooling
   ```

4. **Test GPU stability:**
   ```bash
   # Run GPU stress test
   # If fails, GPU may be faulty
   ```

---

### CPU Mining Not Working

**Symptoms:**
```
[CPU] Prime mining not supported
```

**Solutions:**

1. **Verify build with PRIME support:**
   ```bash
   # Rebuild with Prime support
   cmake -DWITH_PRIME=On ..
   make -j4
   ```

2. **Check dependencies:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libgmp-dev libboost-all-dev
   ```

3. **Verify channel setting:**
   ```toml
   [mining]
   channel = 1  # Must be 1 for Prime (CPU)
   ```

---

## Advanced Diagnostics

### Enable Debug Logging

```toml
[logging]
level = 1  # 0=trace, 1=debug, 2=info
```

**Output to file:**
```bash
./NexusMiner miner.conf > miner.log 2>&1
```

---

### Network Packet Capture

```bash
# Capture mining traffic
sudo tcpdump -i any port 8323 -w mining.pcap

# Analyze with Wireshark
wireshark mining.pcap
```

---

### Check Protocol Opcodes

Look for these in debug logs:

**Stateless protocol:**
- `MINER_AUTH (0xD000)`
- `MINER_AUTH_RESPONSE (0xD001)`
- `MINER_READY (0xD007)`
- `GET_BLOCK (0xD008)`
- `NEW_BLOCK (0xD009)`

**Legacy protocol:**
- `GET_ROUND (0x05)`
- `BLOCK_DATA (0x06)`

**See:** [docs/reference/opcodes-reference.md](../reference/opcodes-reference.md)

---

### System Information

Collect this info for bug reports:

```bash
# NexusMiner version
./NexusMiner --version

# System info
uname -a
cat /etc/os-release

# Hardware info
lscpu
nvidia-smi  # For Nvidia GPUs
rocm-smi    # For AMD GPUs

# Node version
# In Nexus wallet:
system/get/info
```

---

## Additional Resources

### Detailed Guides
- **Enhanced Diagnostics:** [enhanced-diagnostics.md](enhanced-diagnostics.md)
- **Dynamic Port Detection:** [dynamic-port-detection.md](dynamic-port-detection.md)
- **Cross Validation Recovery:** [cross-validation-recovery.md](cross-validation-recovery.md)

### Configuration
- **Configuration Reference:** [docs/reference/nexus.conf.md](../reference/nexus.conf.md)
- **Example Configs:** [docs/reference/config-examples/](../reference/config-examples/)
- **TOML Format Guide:** [docs/reference/toml-format.md](../reference/toml-format.md)

### Protocol Documentation
- **Stateless Mining:** [docs/current/mining-protocols/stateless-mining.md](../current/mining-protocols/stateless-mining.md)
- **Opcodes Reference:** [docs/reference/opcodes-reference.md](../reference/opcodes-reference.md)
- **Migration Guide:** [docs/upgrade-guides/legacy-to-stateless.md](../upgrade-guides/legacy-to-stateless.md)

### Security
- **Genesis-First Protocol:** [docs/current/authentication/genesis-first-protocol.md](../current/authentication/genesis-first-protocol.md)
- **ChaCha20 Encryption:** [docs/current/security/chacha20-encryption.md](../current/security/chacha20-encryption.md)
- **Security Overview:** [docs/current/security/security-overview.md](../current/security/security-overview.md)

---

## Getting Help

If you're still having issues:

1. **Check GitHub Issues:**
   - [NexusMiner Issues](https://github.com/Nexusoft/NexusMiner/issues)
   - Search for similar problems

2. **Join Telegram:**
   - [Nexus Miners](https://t.me/NexusMiners)
   - Community support

3. **Create Bug Report:**
   - Include miner version
   - Include config file (remove private keys!)
   - Include relevant logs
   - Include system information

---

**Last Updated:** January 2026  
**NexusMiner Version:** 1.5+  
**Protocol:** Stateless mining support
