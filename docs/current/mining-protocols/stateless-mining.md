# Stateless Mining Protocol (LLL-TAO PR #170)

> ⚠️ **Historical note**: Some opcode values and protocol flow descriptions in
> this document reflect an earlier design iteration (e.g. opcodes 0xD007,
> 0xD008, 0xD009 for `MINER_READY` / `GET_BLOCK` / `NEW_BLOCK`).  The current
> implementation uses the values documented in
> [PROTOCOL_LANES.md](../../PROTOCOL_LANES.md) and
> [push-notifications.md](push-notifications.md).  Push notifications are now
> sent on **any** channel block (universal PoW tip push) and the miner refreshes
> for two distinct reasons (`channel_advanced` and `tip_moved`).  Refer to
> [unified-tip-vs-channel-height.md](../mining/unified-tip-vs-channel-height.md)
> for the authoritative description.

## Overview

The stateless mining protocol is a modern push-notification based protocol that eliminates polling overhead and provides instant block updates. It represents a significant improvement over the legacy GET_ROUND polling protocol.

## Key Features

✅ **Push Notifications** - Node pushes templates to miner (no polling)  
✅ **Instant Updates** - NEW_BLOCK pushed when blockchain advances  
✅ **Auto-Negotiation** - Automatic fallback to legacy protocol if unsupported  
✅ **Lower Latency** - Immediate template delivery after MINER_READY  
✅ **Reduced Network Traffic** - No periodic GET_ROUND polling required  
✅ **Session-Based** - Maintains persistent connection with keepalive

---

## Protocol Flow

### Initial Connection and Authentication

```
Miner                                    Node
  |                                       |
  |--- MINER_AUTH (0xD000) ------------->|
  |    [genesis(32)][pubkey_len(2)]      |
  |    [pubkey(897/925)][miner_id]       |
  |                                       |
  |<-- MINER_AUTH_RESPONSE (0xD001) -----|
  |    [success(1)][session_id(32)]      |
  |    [nonce(12)][challenge(64)]        |
  |                                       |
```

### Stateless Protocol Negotiation

```
Miner                                    Node
  |                                       |
  |--- MINER_READY (0xD007) ------------>|
  |    (Indicates stateless support)     |
  |                                       |
  |<-- GET_BLOCK (0xD008) ---------------|
  |    [template data]                   |
  |    (Initial mining template)         |
  |                                       |
```

### Mining Loop (Stateless)

```
Miner                                    Node
  |                                       |
  |    ⛏️  Mining block...                 |
  |                                       |
  |<-- NEW_BLOCK (0xD009) ---------------|
  |    [template data]                   |
  |    (Pushed when chain advances)      |
  |                                       |
  |    ⛏️  Switch to new template          |
  |    ⛏️  Continue mining...              |
  |                                       |
  |--- SUBMIT_BLOCK (0x0005) ----------->|
  |    [block data]                      |
  |    (Found valid block)               |
  |                                       |
  |<-- ACCEPT (0x01) or REJECT (0x00) ---|
  |                                       |
```

### Legacy Fallback (if node doesn't support stateless)

```
Miner                                    Node
  |                                       |
  |--- MINER_READY (0xD007) ------------>|
  |                                       |
  |    (No response - node doesn't       |
  |     support stateless protocol)      |
  |                                       |
  |--- GET_ROUND (polling) ------------->|
  |<-- BLOCK_DATA ----------------------|
  |    (Traditional polling mode)        |
  |                                       |
```

---

## Opcodes

### Stateless Tritium Protocol Opcodes (uint16_t, port 9323)

| Opcode | Value | Direction | Description |
|--------|-------|-----------|-------------|
| `MINER_AUTH` | 0xD000 | Miner → Node | Genesis-first authentication |
| `MINER_AUTH_RESPONSE` | 0xD001 | Node → Miner | Authentication result + session |
| `STATELESS_MINER_READY` | 0xD0D8 | Miner → Node | Signal stateless protocol support |
| `STATELESS_PRIME_BLOCK_AVAILABLE` | 0xD0D9 | Node → Miner | Push notification (Prime channel) |
| `STATELESS_HASH_BLOCK_AVAILABLE` | 0xD0DA | Node → Miner | Push notification (Hash channel) |
| `STATELESS_GET_BLOCK` | 0xD081 | Miner → Node | Request mining template |
| `SUBMIT_BLOCK` | 0x0005 | Miner → Node | Submit found block |
| `ACCEPT` / `REJECT` | 0x01 / 0x00 | Node → Miner | Block submission result |

### Legacy Tritium Protocol Opcodes (uint8_t, port 8323)

| Opcode | Value | Direction | Description |
|--------|-------|-----------|-------------|
| `PRIME_BLOCK_AVAILABLE` | 0xD9 | Node → Miner | Push notification (Prime channel) |
| `HASH_BLOCK_AVAILABLE` | 0xDA | Node → Miner | Push notification (Hash channel) |
| `GET_ROUND` | 0x05 | Miner → Node | Poll for template (legacy) |
| `BLOCK_DATA` | 0x06 | Node → Miner | Template response (legacy) |

**See:** [docs/reference/opcodes-reference.md](../../reference/opcodes-reference.md) for complete opcode reference.

---

## Push Notification Flow (Post-PR #122)

After authentication and channel selection:

1. Miner sends: `STATELESS_MINER_READY (0xD0D8)`
2. Node immediately sends: `STATELESS_PRIME_BLOCK_AVAILABLE (0xD0D9)` or `STATELESS_HASH_BLOCK_AVAILABLE (0xD0DA)`
3. Payload: 12 bytes [unified_height, channel_height, difficulty]
4. Miner requests template: `STATELESS_GET_BLOCK (0xD081)`
5. Node sends: 228-byte template [12 metadata + 216 block]
6. On new block: Node pushes step 2 again (event-driven, no polling)

---

## Packet Formats

### MINER_AUTH (0xD000)

**Genesis-First Authentication Packet**

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0      | 32   | hashGenesis    | Tritium account genesis hash
32     | 2    | pubkey_len     | Falcon public key length
34     | 897  | falcon_pubkey  | Falcon-512 public key (unwrapped)
       | or   |                | OR
34     | 925  | falcon_pubkey  | Falcon-512 public key (ChaCha20 wrapped)
       |      |                | [nonce(12)][ciphertext(897)][tag(16)]
931    | 2    | miner_id_len   | Miner ID string length
933    | var  | miner_id       | Miner ID string (e.g., "NexusMiner")
```

**Notes:**
- Genesis hash sent FIRST enables key derivation before pubkey parsing
- ChaCha20 wrapping auto-enabled for remote mining
- Session key = SHA256("nexus-mining-chacha20-v1" || genesis)

**See:** [docs/current/authentication/genesis-first-protocol.md](../authentication/genesis-first-protocol.md)

---

### MINER_AUTH_RESPONSE (0xD001)

**Authentication Result + Session Establishment**

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0      | 1    | success        | 1=success, 0=failure
1      | 32   | session_id     | Session identifier
33     | 12   | nonce          | ChaCha20 nonce for challenge
45     | 64   | challenge      | Encrypted challenge data (for future use)
```

---

### MINER_READY (0xD007)

**Stateless Protocol Signal**

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
(empty packet - just opcode)
```

**Purpose:**
- Signals to node that miner supports stateless protocol
- Node responds with GET_BLOCK if supported
- No response = node doesn't support, fallback to legacy GET_ROUND

---

### GET_BLOCK (0xD008)

**Initial Template Push**

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0      | var  | template       | Mining template data
       |      |                | (format matches legacy BLOCK_DATA)
```

**Trigger:**
- Sent immediately after receiving MINER_READY
- Contains current best template for mining

---

### NEW_BLOCK (0xD009)

**Updated Template Push**

```
Offset | Size | Field          | Description
-------|------|----------------|----------------------------------
0      | var  | template       | Updated mining template data
       |      |                | (format matches legacy BLOCK_DATA)
```

**Trigger:**
- Pushed when blockchain advances (new block found)
- Pushed when template becomes stale
- Miner should immediately switch to new template

---

## Auto-Negotiation Process

The miner automatically detects whether the connected node supports stateless protocol:

### Step 1: Authentication
```cpp
// Miner sends MINER_AUTH with genesis-first format
send_packet(MINER_AUTH, auth_data);

// Wait for MINER_AUTH_RESPONSE
auto response = recv_packet();
if (response.opcode == MINER_AUTH_RESPONSE && response.success) {
    session_established = true;
}
```

### Step 2: Protocol Negotiation
```cpp
// Attempt stateless protocol
send_packet(MINER_READY);

// Wait for response with timeout
auto response = recv_packet_with_timeout(5s);

if (response.opcode == GET_BLOCK) {
    // ✅ Node supports stateless protocol
    stateless_mode = true;
    current_template = parse_template(response.data);
    start_mining();
} else {
    // ❌ Node doesn't support stateless
    // Fallback to legacy polling
    stateless_mode = false;
    start_legacy_polling();
}
```

### Step 3: Mining Loop

**Stateless Mode:**
```cpp
while (mining) {
    // Mine current template
    mine_template(current_template);
    
    // Listen for NEW_BLOCK pushes
    if (packet_received(NEW_BLOCK)) {
        current_template = parse_template(packet.data);
        restart_mining();
    }
    
    // Submit found blocks
    if (block_found) {
        send_packet(SUBMIT_BLOCK, block_data);
        wait_for_accept_or_reject();
    }
}
```

**Legacy Mode:**
```cpp
while (mining) {
    // Poll for template periodically
    sleep(poll_interval);
    send_packet(GET_ROUND);
    
    auto response = recv_packet();
    if (response.opcode == BLOCK_DATA) {
        current_template = parse_template(response.data);
    }
    
    // Mine and submit as usual
    mine_and_submit();
}
```

---

## Implementation Details

### Keepalive Mechanism

To maintain session cache on the node:

```cpp
// Default keepalive interval: 24 hours
const auto keepalive_interval = config.keepalive_interval_hours;

// Send periodic keepalive pings
timer.schedule_periodic(keepalive_interval, []() {
    send_packet(KEEPALIVE_PING);
});
```

**See:** [docs/current/authentication/falcon-handshake-cache.md](../authentication/falcon-handshake-cache.md)

---

### Session Recovery

If connection is lost:

```cpp
// On disconnect
if (connection_lost) {
    // Re-authenticate with same genesis/keys
    send_packet(MINER_AUTH, auth_data);
    
    // Node may restore session from cache
    // Or create new session if cache expired
    auto response = recv_packet(MINER_AUTH_RESPONSE);
    
    // Resume stateless protocol
    if (response.success) {
        send_packet(MINER_READY);
        // Continue mining
    }
}
```

---

## Logging Output

### Successful Stateless Connection

```
[Falcon Auth] ✅ Authentication successful
[Falcon Auth]    Session ID: a1b2c3d4...
[Solo Protocol] Attempting stateless protocol (MINER_READY 0xD007)
[Solo Protocol] ✅ Stateless protocol ACTIVE
[Solo Stateless] ✨ STATELESS_GET_BLOCK (0xD008) received!
[Solo Stateless]    Channel: 1 (Prime)
[Solo Stateless]    Height: 4523891
[Mining] ⛏️  Started mining on template...
```

### NEW_BLOCK Notification

```
[Solo Stateless] 🔔 NEW_BLOCK (0xD009) notification received!
[Solo Stateless]    New height: 4523892
[Solo Stateless]    Switching to new template...
[Mining] ⛏️  Restarted mining on new template
```

### Legacy Fallback

```
[Solo Protocol] Attempting stateless protocol (MINER_READY 0xD007)
[Solo Protocol] ⚠️  No response - node doesn't support stateless
[Solo Protocol] ℹ️  Falling back to legacy GET_ROUND polling
[Legacy Mining] 🔄 Polling for template every 5 seconds...
```

---

## Performance Comparison

### Stateless Protocol

| Metric | Value |
|--------|-------|
| **Template Latency** | < 10ms (instant push) |
| **Network Traffic** | ~100 bytes/block (NEW_BLOCK only) |
| **CPU Overhead** | Minimal (event-driven) |
| **Stale Work** | Near zero (instant updates) |

### Legacy Polling Protocol

| Metric | Value |
|--------|-------|
| **Template Latency** | 1-5 seconds (poll interval) |
| **Network Traffic** | ~500 bytes/sec (continuous polling) |
| **CPU Overhead** | Higher (polling loop) |
| **Stale Work** | 1-5 seconds worth per block |

**Efficiency Gain:** ~95% reduction in network traffic, <90% reduction in template latency

---

## Node Requirements

### Node Support Detection

Stateless protocol requires:
- LLL-TAO node with PR #170 or later
- `miningport` enabled (default: 8323)
- Falcon authentication enabled

**Check node version:**
```bash
# In Nexus wallet console:
system/get/info

# Look for version >= 5.1.0 or stateless mining support
```

---

## Configuration

### Miner Configuration

**No special configuration needed!** The miner automatically:
1. Attempts stateless protocol
2. Falls back to legacy if unsupported
3. Uses optimal protocol for the connected node

**Example miner.conf (TOML):**
```toml
[wallet]
ip = "127.0.0.1"
port = 8323  # Stateless mining port

[mining]
channel = 1
genesis = "your_genesis_hash"
reward_address = "your_nxs_address"

[falcon]
pubkey = "your_falcon_pubkey"
privkey = "your_falcon_privkey"
```

**See:** [docs/reference/nexus.conf.md](../../reference/nexus.conf.md) for complete configuration reference.

---

### Node Configuration

**Example nexus.conf:**
```ini
# Enable mining
mining=1

# Mining port (default: 8323)
miningport=8323

# Whitelist miner public keys (optional)
# minerallowkey=<falcon_pubkey_hex>
```

---

## Troubleshooting

### "No stateless protocol support detected"

**Possible causes:**
1. Node version too old (< 5.1.0)
2. Node doesn't have PR #170
3. Mining not enabled on node

**Solution:**
- Update node to latest version
- Verify `mining=1` in nexus.conf
- Check node logs for mining server startup

---

### "Connection lost during mining"

**Possible causes:**
1. Network interruption
2. Node restart
3. Session expired (keepalive not working)

**Solution:**
- Miner will auto-reconnect
- Check keepalive_interval setting
- Verify network stability

---

### "Falling back to legacy protocol"

**This is normal!** The miner is designed to work with both new and old nodes.

**If you want stateless protocol:**
- Ensure node supports it (version check)
- Verify `port = 8323` in miner config
- Check node logs for stateless protocol messages

---

## Security Considerations

### Session Security

- Session IDs are cryptographically random (32 bytes)
- Genesis binding ensures rewards go to correct account
- ChaCha20 encryption protects public key in transit
- Falcon signatures provide quantum-resistant authentication

**See:** [docs/current/security/security-overview.md](../security/security-overview.md)

---

### Replay Protection

- Each authentication generates new session ID
- Nonces ensure unique encryption for each packet
- Session expiration prevents long-term replay attacks

---

## Migration from Legacy Protocol

### For Users

**No action required!** The miner automatically:
- Detects node capabilities
- Uses best available protocol
- Falls back gracefully if needed

### For Node Operators

**To enable stateless protocol:**
1. Update to LLL-TAO with PR #170+
2. Ensure `mining=1` in nexus.conf
3. Use `miningport=8323` (default)
4. Miners will auto-detect and use stateless protocol

**See:** [docs/upgrade-guides/legacy-to-stateless.md](../../upgrade-guides/legacy-to-stateless.md)

---

## References

- **Implementation PR:** LLL-TAO PR #170
- **Miner PR:** NexusMiner PR #91
- **Opcode Reference:** [docs/reference/opcodes-reference.md](../../reference/opcodes-reference.md)
- **Genesis-First Protocol:** [docs/current/authentication/genesis-first-protocol.md](../authentication/genesis-first-protocol.md)
- **Configuration Reference:** [docs/reference/nexus.conf.md](../../reference/nexus.conf.md)

---

**Status:** ✅ Production Ready  
**Version:** NexusMiner 1.5+  
**Node Version:** LLL-TAO 5.1.0+ (with PR #170)  
**Last Updated:** January 2026
