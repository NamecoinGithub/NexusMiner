# Data Packet Structure Documentation

## Overview

The Data Packet is a wrapper structure for block submissions that includes a Falcon signature, enabling nodes to verify the miner's identity while keeping the signature separate from the blockchain. This design helps reduce blockchain size over time by not storing signatures in the block template itself.

## Purpose

1. **Blockchain Size Reduction**: Signatures are verified and discarded by nodes, not stored on-chain
2. **Miner Authentication**: Cryptographically prove which miner found the block solution
3. **Non-repudiation**: Prevent miners from denying they submitted a particular block
4. **Security Enhancement**: Quantum-resistant authentication via Falcon-512 signatures

## Structure

The Data Packet contains three components:

```
+------------------+--------+----------------------------------------------+
| Field            | Size   | Description                                  |
+------------------+--------+----------------------------------------------+
| Merkle Root      | 64 B   | Block's merkle root (uint512_t)             |
| Nonce            | 8 B    | Solution nonce (uint64_t, big-endian)       |
| Signature Length | 2 B    | Length of signature (uint16_t, big-endian)  |
| Signature        | ~690 B | Falcon-512 signature over (root + nonce)    |
+------------------+--------+----------------------------------------------+
Total: ~764 bytes (64 + 8 + 2 + 690)
```

### Field Details

#### 1. Merkle Root (64 bytes)
- **Type**: `uint512_t` serialized to bytes
- **Format**: Big-endian byte array
- **Source**: From `block.hashMerkleRoot.GetBytes()`
- **Purpose**: Identifies the block being submitted

#### 2. Nonce (8 bytes)
- **Type**: `uint64_t`
- **Format**: Big-endian
- **Source**: The nonce value that solves the block
- **Purpose**: The proof-of-work solution

#### 3. Signature (variable, ~690 bytes for Falcon-512)
- **Type**: Falcon-512 signature
- **Format**: Raw signature bytes prefixed with 2-byte big-endian length
- **Signed Data**: `merkle_root (64 bytes) + nonce (8 bytes, big-endian)`
- **Purpose**: Cryptographic proof of miner identity

## Protocol Integration

### Opcode: SUBMIT_DATA_PACKET (14)

**Direction**: Miner → Node  
**Purpose**: Submit solved block with Falcon signature wrapper  
**Payload**: Serialized Data Packet (see structure above)

### Usage in Mining Flow

```
Miner                                    Node
  |                                       |
  | (mining happens, block found)        |
  |                                       |
  |--- SUBMIT_DATA_PACKET (14) --------->|
  |    [merkle_root(64)]                 |
  |    [nonce(8, BE)]                    |
  |    [sig_len(2, BE)]                  |
  |    [signature(~690)]                 |
  |                                       |
  |<-- BLOCK_ACCEPTED (200) -------------|
  | or BLOCK_REJECTED (201)              |
  |                                       |
```

### When to Use Data Packet vs Legacy Submit

**Use SUBMIT_DATA_PACKET (14) when**:
- Miner has Falcon keypair configured
- Solo mining to LLL-TAO node with Phase 2+ support
- Node requires miner identity verification

**Use SUBMIT_BLOCK (1) when**:
- No Falcon keys available
- Pool mining
- Legacy compatibility mode
- Node doesn't support Data Packet

## Implementation

### NexusMiner Side (Client)

The Data Packet is automatically used when:
1. Falcon keys are configured in `miner.conf`
2. Mining in SOLO mode (not pool)
3. Connection established successfully

Code flow:
```cpp
// In worker_manager.cpp - block found callback
auto solo_protocol = std::dynamic_pointer_cast<protocol::Solo>(m_miner_protocol);
if (solo_protocol && config.has_miner_falcon_keys())
{
    // Use Data Packet with signature
    connection->transmit(solo_protocol->submit_data_packet(
        block_data->merkle_root.GetBytes(), block_data->nNonce));
}
else
{
    // Use legacy submit_block (no signature)
    connection->transmit(m_miner_protocol->submit_block(
        block_data->merkle_root.GetBytes(), block_data->nNonce));
}
```

### LLL-TAO Side (Node)

The node must implement:

1. **Receive SUBMIT_DATA_PACKET**
   ```cpp
   case SUBMIT_DATA_PACKET:
   {
       // Deserialize Data Packet
       llp::DataPacket packet = llp::DataPacket::deserialize(payload);
       
       // Extract miner's public key from session
       auto pubkey = get_session_pubkey(session_id);
       
       // Verify Falcon signature
       if (!falcon_verify(pubkey, packet.merkle_root + packet.nonce, packet.signature))
       {
           return BLOCK_REJECTED;
       }
       
       // Process block normally (don't store signature on-chain)
       process_block_submission(packet.merkle_root, packet.nonce);
   }
   ```

2. **Session Management**
   - Track authenticated sessions with public keys
   - Associate submissions with miner identities
   - Log miner activity for attribution

3. **Signature Verification**
   - Use Falcon library to verify signatures
   - Check against whitelisted public keys
   - Reject blocks with invalid signatures

## Code Structure

### Files Added/Modified

1. **src/LLP/data_packet.hpp** (NEW)
   - `DataPacket` struct with serialize/deserialize methods
   - Validation and error handling

2. **src/LLP/miner_opcodes.hpp** (MODIFIED)
   - Added `SUBMIT_DATA_PACKET = 14` opcode

3. **src/LLP/packet.hpp** (MODIFIED)
   - Added `SUBMIT_DATA_PACKET` to packet enum

4. **src/LLP/llp_logging.hpp** (MODIFIED)
   - Added logging support for `SUBMIT_DATA_PACKET`

5. **src/protocol/inc/protocol/solo.hpp** (MODIFIED)
   - Added `submit_data_packet()` method

6. **src/protocol/src/protocol/solo.cpp** (MODIFIED)
   - Implemented `submit_data_packet()` with signing logic
   - Automatic fallback to legacy `submit_block()` on errors

7. **src/worker_manager.cpp** (MODIFIED)
   - Smart selection between Data Packet and legacy submit based on configuration

## Configuration

No new configuration is required. The Data Packet feature is automatically enabled when Falcon keys are present in `miner.conf`:

```json
{
    "miner_falcon_pubkey": "<hex_encoded_pubkey>",
    "miner_falcon_privkey": "<hex_encoded_privkey>"
}
```

Generate keys with:
```bash
./NexusMiner --create-falcon-config
```

## Backward Compatibility

- ✅ **Legacy nodes**: Miners automatically fall back to SUBMIT_BLOCK when no Falcon keys
- ✅ **Pool mining**: Continues to use SUBMIT_BLOCK (Data Packet not used)
- ✅ **No Falcon keys**: Uses SUBMIT_BLOCK without signature
- ✅ **Node doesn't support opcode 14**: Connection may reject packet, miner can retry with SUBMIT_BLOCK

## Security Considerations

### Signature Security

1. **What is signed**: `merkle_root (64 bytes) + nonce (8 bytes)` = 72 bytes
2. **Signature algorithm**: Falcon-512 (NIST PQC candidate)
3. **Key size**: Public key ~897 bytes, private key ~1281 bytes
4. **Signature size**: ~690 bytes (variable, depends on Falcon internal compression)

### Attack Vectors

1. **Signature replay**: Node must track submitted blocks to prevent replay
2. **Key compromise**: Protect private keys with filesystem permissions
3. **Man-in-the-middle**: Use TLS/SSL for transport encryption (future enhancement)
4. **Signature forgery**: Mathematically infeasible with Falcon-512

### Best Practices

1. **Private key storage**: Never commit private keys to version control
2. **Key rotation**: Generate new keypair periodically
3. **Public key whitelist**: Node operators should maintain authorized miner list
4. **Session management**: Nodes should expire idle sessions

## Testing

### Unit Tests

Test the Data Packet serialization/deserialization:

```cpp
// Test 1: Basic serialization
DataPacket packet;
packet.merkle_root = /* 64 bytes */;
packet.nonce = 123456789;
packet.signature = /* valid signature */;
auto serialized = packet.serialize();
auto deserialized = DataPacket::deserialize(serialized);
assert(deserialized.nonce == packet.nonce);

// Test 2: Invalid merkle root size
DataPacket bad_packet;
bad_packet.merkle_root = /* 32 bytes - wrong! */;
// Should throw std::runtime_error
```

### Integration Tests

1. **Solo mining with Data Packet**:
   - Configure Falcon keys
   - Mine a block
   - Verify SUBMIT_DATA_PACKET is sent (check logs)
   - Verify block is accepted by node

2. **Fallback to legacy**:
   - Remove Falcon keys from config
   - Mine a block
   - Verify SUBMIT_BLOCK is sent (not SUBMIT_DATA_PACKET)

3. **Signature verification**:
   - Node receives Data Packet
   - Verifies signature with miner's public key
   - Accepts valid signatures, rejects invalid ones

## Performance Impact

### Network Bandwidth

- **Data Packet**: ~764 bytes per submission
- **Legacy Submit**: 72 bytes per submission
- **Overhead**: +692 bytes (~10x larger)

**Justification**: The signature is NOT stored on-chain, so blockchain size is unaffected. The network overhead is acceptable for enhanced security and miner attribution.

### CPU Impact

- **Signing**: ~1-2 ms per block (Falcon-512 is very fast)
- **Verification**: ~0.5-1 ms per block (on node side)
- **Negligible impact** on mining performance

## Future Enhancements

1. **Batch submissions**: Sign multiple blocks in one Data Packet
2. **Signature compression**: Reduce signature size further
3. **Public key reference**: Send keyId instead of full pubkey for known miners
4. **Challenge-response**: Add timestamp or session nonce to prevent replay
5. **TLS encryption**: Add transport-layer security for end-to-end encryption

## LLL-TAO Integration Checklist

For LLL-TAO developers implementing Data Packet support:

- [ ] Add `SUBMIT_DATA_PACKET = 14` to `src/LLP/types/miner.h`
- [ ] Implement packet handler in stateless miner LLP server
- [ ] Add `llp::DataPacket` deserializer (or use NexusMiner's implementation)
- [ ] Track session → public key mapping
- [ ] Verify Falcon signature before accepting block
- [ ] Process block normally after signature verification
- [ ] Do NOT store signature in blockchain
- [ ] Log miner attribution for analytics
- [ ] Add configuration for requiring Data Packet vs allowing legacy

## Example Log Output

### NexusMiner (Miner Side)

```
[Solo Data Packet] Submitting block with Data Packet wrapper...
[Solo Data Packet] Signed block data (signature: 690 bytes)
[Solo Data Packet] Data Packet size: 764 bytes (merkle: 64, nonce: 8, sig: 690)
[Solo Data Packet] Submitting authenticated Data Packet (session: 0x12345678)
[LLP SEND] header=14 (SUBMIT_DATA_PACKET) Length=764
Block Accepted By Nexus Network.
```

### LLL-TAO (Node Side)

```
[Miner LLP] Received SUBMIT_DATA_PACKET from session 0x12345678
[Miner LLP] Data Packet: merkle=abc123..., nonce=987654321, sig_len=690
[Miner LLP] Verifying Falcon signature with miner pubkey...
[Miner LLP] ✓ Signature verified successfully
[Miner LLP] Processing block submission (merkle + nonce)
[Blockchain] Block accepted at height 12345
[Miner LLP] Sending BLOCK_ACCEPTED to miner
```

## Conclusion

The Data Packet structure provides a secure, quantum-resistant way to attribute block solutions to specific miners without inflating the blockchain. It integrates seamlessly with the existing Falcon authentication system and provides automatic fallback to legacy mode for backward compatibility.

---

**Last Updated**: 2025-11-25  
**Feature Version**: 1.0  
**Author**: NexusMiner Development Team
