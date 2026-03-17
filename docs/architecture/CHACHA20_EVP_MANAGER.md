# ChaCha20 EVP Manager — Architecture & Design Reference

## Overview

`ChaCha20EVPManager` is the **unified encryption mode gate** for NexusMiner's dual-lane protocol architecture. It acts as the single point of authority for deciding whether a given node instance uses:

- **EVP (ChaCha20-Poly1305 via OpenSSL EVP)** — default for all remote connections
- **TLS (TLS 1.2/1.3 via ASIO SSL)** — opt-in, configured at node startup
- **NONE** — plaintext, for localhost-only mining where transport overhead is undesirable

Both the **Legacy Lane** (port 8323) and the **Stateless Lane** (port 9323) consult this singleton for every packet that crosses a connection boundary.

---

## Files

| File | Role |
|------|------|
| `src/protocol/inc/protocol/chacha20_evp_manager.hpp` | Public header — `ChaCha20EVPManager` singleton, `EncryptionMode` enum, `EVPPacketResult`, `SessionKeyEntry` |
| `src/protocol/src/protocol/chacha20_evp_manager.cpp` | Implementation — delegates crypto to `ChaCha20Wrapper` |

### Files NOT Modified (existing, untouched)

| File | Role |
|------|------|
| `src/protocol/inc/protocol/chacha20_wrapper.hpp` | `ChaCha20Wrapper` — low-level ChaCha20-Poly1305 EVP wrapper |
| `src/protocol/src/protocol/chacha20_wrapper.cpp` | Implementation of `ChaCha20Wrapper` |
| `src/network/src/network/tls/tls_context.cpp` | ASIO SSL TLS context (TLS 1.2/1.3) |
| `src/network/inc/network/tls/tls_context.hpp` | TLS context header |

---

## Design Invariants

### 1. Either/Or: EVP and TLS Cannot Coexist

EVP and TLS are **mutually exclusive** for the entire node instance — not per-lane, not per-connection. If TLS is active, **both** lanes use TLS. If EVP/ChaCha20 is active, **both** lanes use ChaCha20 EVP. There is no scenario where one lane uses TLS and the other uses EVP.

This is enforced in `configure()`: the mode is a node-global setting. `lock_mode()` freezes it once the first connection is accepted, preventing mid-flight switching.

### 2. EVP Is the Default

After this PR, `EncryptionMode::EVP` (ChaCha20-Poly1305) is the default mode for remote connections. TLS remains available as an **opt-in** — it must be explicitly selected at node startup and cannot be toggled at runtime.

### 3. Delegation, Not Re-implementation

`ChaCha20EVPManager` does **not** re-implement ChaCha20. All cryptographic operations delegate directly to the existing `ChaCha20Wrapper` via its public API (`encrypt()`, `decrypt()`, `generate_nonce()`). The manager adds the session-keying layer and mode gate on top.

### 4. Shared Singleton Across Both Lanes

Both lanes access the same `ChaCha20EVPManager::Get()` singleton. A session key registered after auth on the Legacy Lane is automatically available to the Stateless Lane for the same session ID.

### 5. Session Key Lifecycle

- **Register**: `register_session(nSessionId, session_key, fingerprint)` — called after successful MINER_AUTH handshake
- **Use**: `encrypt_packet()` / `decrypt_packet()` — hot path, per-packet
- **Remove**: `remove_session(nSessionId)` — on disconnect/expiry
- **Prune**: `prune_expired_sessions(live_sessions)` — called from `CleanupExpiredSessions()` periodic task

Key material is explicitly zeroed before erasure to reduce key-in-memory window.

---

## Wire Format

For EVP-mode packets:

```
[nonce: 12 bytes][ciphertext + Poly1305 tag: N+16 bytes]
```

- Nonce: fresh 12-byte random value generated per packet via `ChaCha20Wrapper::generate_nonce()`
- Ciphertext: ChaCha20-Poly1305 encrypted payload
- Tag: 16-byte Poly1305 authentication tag (appended by OpenSSL EVP)

Minimum valid wire payload: **28 bytes** (12-byte nonce + 16-byte tag, zero-length plaintext).

---

## Thread Safety

All public methods acquire `m_mutex`. The hot-path `encrypt_packet()` and `decrypt_packet()` methods:

1. Acquire the mutex to read mode + copy the session key
2. Release the mutex
3. Call into `ChaCha20Wrapper` (which is internally thread-safe) without holding the manager lock

This minimises lock contention on the packet hot-path.

---

## Usage Pattern

```cpp
// At node startup (before any connections):
ChaCha20EVPManager::Get().configure(EncryptionMode::EVP);  // or TLS / NONE

// When first connection is accepted:
ChaCha20EVPManager::Get().lock_mode();

// After successful MINER_AUTH handshake:
ChaCha20EVPManager::Get().register_session(nSessionId, session_key, fingerprint);

// On every outgoing packet (both lanes):
auto result = ChaCha20EVPManager::Get().encrypt_packet(nSessionId, plaintext, aad);
if (!result.success) { /* handle error */ }
send(result.data);

// On every incoming packet (both lanes):
auto result = ChaCha20EVPManager::Get().decrypt_packet(nSessionId, wire_bytes, aad);
if (!result.success) { /* handle error */ }
process(result.data);

// On session disconnect / expiry:
ChaCha20EVPManager::Get().remove_session(nSessionId);

// In CleanupExpiredSessions() periodic task:
auto pruned = ChaCha20EVPManager::Get().prune_expired_sessions(live_session_ids);
```

---

## PR #416 (LLL-TAO) Review Notes

### Confirmed Working / Correct

1. ✅ `SharedGetBlockHandler` correctly routes both lanes through the same session-scoped rate limiter (`m_mapSessionLimiters`, keyed by session ID). `shared_ptr` reference counting is correct — the limiter object lives past the lock window.

2. ✅ `StoreSessionBlock` / `FindSessionBlock` / `PruneSessionBlocks` are correctly mutex-protected (`m_sessionBlockMutex`) and use independent copies (via copy constructor) so the per-connection `mapBlocks` remains primary owner.

3. ✅ `GetBlockResult` payload invariant is respected: if `fSuccess == true`, `vPayload` is always 228 bytes (documented in `get_block_handler.h`).

4. ✅ SIM-Link deduplication in `ColinMiningAgent::check_and_record_submission()` correctly prevents double-accept when both lanes submit near-simultaneously.

5. ✅ `SessionConsistencyResult` gate at SUBMIT_BLOCK is correctly placed before block lookup on both the legacy lane (`miner.cpp`) and stateless lane (`stateless_miner_connection.cpp`).

### Known Limitations

1. ⚠️ `FindSessionBlock()` is not yet wired into either SUBMIT_BLOCK handler's per-connection `find_block()` fallback — cross-lane template resolution is infrastructure-only, not active. This is the intended follow-up.

2. ⚠️ `m_mapSessionLimiters` has no periodic cleanup; tied to `CleanupExpiredSessions()` which is currently call-invoked but not timer-driven. Will grow slowly with unique session count. Non-critical for current scale.

3. ⚠️ Legacy lane session ID lookup via `GetAddress().ToStringIP() + ":" + port` is connection-address–scoped. Same miner from two IPs = different session IDs on legacy lane. Fundamental limitation of legacy port identity model.

**No blocking errors found.** PR #415 (merged) and PR #416 are correct within their stated scope.

---

## Follow-Up Work (Not in This PR)

*(All items below were completed in the follow-up wire-in PR.)*

---

## Wire-In Status (Follow-Up PR)

### Completed ✅

| Item | File | Change |
|------|------|--------|
| `configure(EVP)` at startup | `src/miner.cpp::Miner::init()` | Called after logger is set up, before connections |
| `lock_mode()` before first connection | `src/miner.cpp::Miner::run()` | Called just before `m_worker_manager->connect()` |
| `register_session()` after auth | `src/protocol/src/protocol/solo.cpp::on_miner_auth_response()` | Called after `commit_authenticated_session()`, uses `chacha20_session_key` from session context |
| `remove_session()` on expiry | `src/protocol/src/protocol/solo.cpp::handle_session_expired()` | Called before `m_session_id` is zeroed |
| `remove_session()` on reset | `src/protocol/src/protocol/solo.cpp::reset()` | Called if `m_session_id != 0` before zero |
| `prune_expired_sessions({})` on reset | `src/protocol/src/protocol/solo.cpp::reset()` | Cleans up any stale keys on full session reset |
| EVP encrypt outbound SESSION_KEEPALIVE | `src/protocol/src/protocol/session_manager.cpp::build_keepalive_packet()` | Gate: `is_evp_active() && has_session_key(session_id)` |
| EVP encrypt outbound SESSION_STATUS | `src/protocol/src/protocol/session_manager.cpp::build_session_status_packet()` | Gate: `is_evp_active() && has_session_key(session_id)` |
| EVP decrypt inbound SESSION_STATUS_ACK | `src/protocol/src/protocol/solo.cpp::on_session_status_ack()` | Gate: `is_evp_active() && has_session_key(m_session_id)` |
| Unit tests | `src/protocol/chacha20_evp_manager_test.cpp` | Round-trip, remove/encrypt failure, prune, MITM simulation, mode gate |

### EVP-Encrypted Packet Opcodes (MITM Hardening)

The following opcodes carry `SessionID` in their payload and are now protected
by ChaCha20-Poly1305 EVP encryption when `EncryptionMode::EVP` is active:

| Direction | Opcode | Legacy | Stateless |
|-----------|--------|--------|-----------|
| Miner → Node | SESSION_KEEPALIVE | `0xD4` (212) | `0xD0D4` |
| Miner → Node | SESSION_STATUS | `0xDB` (219) | `0xD0DB` |
| Node → Miner | SESSION_STATUS_ACK | `0xDC` (220) | `0xD0DC` |

AAD for each packet is the opcode byte(s) in little-endian order, providing
domain separation between packet types.

### Deployment Note

The outbound SESSION_KEEPALIVE / SESSION_STATUS encryption and the inbound
SESSION_STATUS_ACK decryption form a coordinated pair: both the miner (this
PR) and the node (LLL-TAO follow-up PR to #417) must be deployed together for
the EVP gate to activate for these packet types. The gate check
(`is_evp_active() && has_session_key(...)`) ensures that plaintext mode is
used automatically during the transition window when only one side is upgraded.
