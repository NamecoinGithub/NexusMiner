# LLL-TAO Node Integration Guide: Data Packet Support

## Overview

This guide explains how to implement Data Packet support in the LLL-TAO node to work with NexusMiner's Data Packet feature. The Data Packet wraps block submissions with a Falcon signature that is verified by the node but NOT stored on the blockchain, reducing blockchain size over time.

## Why Data Packet?

**Problem**: Block signatures take up significant space on the blockchain  
**Solution**: Verify miner signatures at submission time, then discard them  
**Result**: Blockchain stores only essential data (merkle_root + nonce)

### Benefits

1. **Reduced Blockchain Size**: Signatures (~690 bytes each) are not stored on-chain
2. **Miner Attribution**: Nodes can track which miner found which block
3. **Enhanced Security**: Quantum-resistant proof of miner identity
4. **Analytics**: Track miner performance and contribution without blockchain bloat
5. **Fraud Prevention**: Prevents miners from denying they submitted specific blocks

## Implementation Requirements

### 1. Add Opcode to LLL-TAO

**File**: `src/LLP/types/miner.h`

```cpp
namespace LLP
{
    enum MinerOpcodes : uint8_t
    {
        // ... existing opcodes ...
        SUBMIT_BLOCK = 1,
        
        /** 
         * SUBMIT_DATA_PACKET: Block submission with Falcon signature wrapper
         * Payload: [merkle_root(64)][nonce(8,BE)][sig_len(2,BE)][signature]
         * The signature is verified but NOT stored on blockchain
         */
        SUBMIT_DATA_PACKET = 14,
        
        // ... rest of opcodes ...
    };
}
```

### 2. Create DataPacket Structure

**File**: `src/LLP/data_packet.h` (NEW)

```cpp
#ifndef NEXUS_LLP_DATA_PACKET_H
#define NEXUS_LLP_DATA_PACKET_H

#include <LLC/types/uint1024.h>
#include <vector>
#include <cstdint>

namespace LLP
{
    /**
     * Data Packet structure for block submissions with Falcon signatures.
     * The signature is verified by the node but NOT stored in the blockchain.
     */
    struct DataPacket
    {
        /** Merkle root (64 bytes for uint512) */
        uint512_t merkle_root;
        
        /** Nonce value */
        uint64_t nonce;
        
        /** Falcon signature over (merkle_root + nonce) */
        std::vector<uint8_t> signature;
        
        /**
         * Deserialize Data Packet from network payload
         * @param data The received payload bytes
         * @return true if deserialization succeeded
         */
        bool Deserialize(const std::vector<uint8_t>& data)
        {
            // Minimum size: 64 (merkle) + 8 (nonce) + 2 (sig_len) = 74 bytes
            if (data.size() < 74) {
                debug::error(FUNCTION, "Data Packet too small: ", data.size(), " bytes");
                return false;
            }
            
            size_t offset = 0;
            
            // 1. Merkle root (64 bytes)
            std::vector<uint8_t> merkle_bytes(data.begin(), data.begin() + 64);
            merkle_root.SetBytes(merkle_bytes);
            offset += 64;
            
            // 2. Nonce (8 bytes, big-endian)
            nonce = 0;
            for (int i = 0; i < 8; ++i) {
                nonce = (nonce << 8) | data[offset + i];
            }
            offset += 8;
            
            // 3. Signature length (2 bytes, big-endian)
            uint16_t sig_len = (static_cast<uint16_t>(data[offset]) << 8) |
                               static_cast<uint16_t>(data[offset + 1]);
            offset += 2;
            
            // 4. Signature bytes
            if (data.size() < offset + sig_len) {
                debug::error(FUNCTION, "Data Packet: insufficient data for signature");
                return false;
            }
            
            signature.assign(data.begin() + offset, data.begin() + offset + sig_len);
            
            return true;
        }
        
        /**
         * Get the data that was signed (for verification)
         * @return merkle_root + nonce as byte vector
         */
        std::vector<uint8_t> GetSignedData() const
        {
            std::vector<uint8_t> data;
            data.reserve(72);
            
            // Merkle root (64 bytes)
            auto merkle_bytes = merkle_root.GetBytes();
            data.insert(data.end(), merkle_bytes.begin(), merkle_bytes.end());
            
            // Nonce (8 bytes, big-endian)
            for (int i = 7; i >= 0; --i) {
                data.push_back(static_cast<uint8_t>(nonce >> (i * 8)));
            }
            
            return data;
        }
    };
}

#endif
```

### 3. Update Miner LLP Handler

**File**: `src/LLP/miner.cpp` (or stateless_miner.cpp for Phase 2)

Add handler for SUBMIT_DATA_PACKET in the packet processing switch:

```cpp
case SUBMIT_DATA_PACKET:
{
    debug::log(2, FUNCTION, "Received SUBMIT_DATA_PACKET from miner");
    
    // Check if session is authenticated
    if (!fMinerAuthenticated) {
        debug::warning(FUNCTION, "Data Packet received but session not authenticated");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    // Deserialize Data Packet
    DataPacket data_packet;
    if (!data_packet.Deserialize(INCOMING.DATA)) {
        debug::error(FUNCTION, "Failed to deserialize Data Packet");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    debug::log(2, FUNCTION, "Data Packet: merkle=", data_packet.merkle_root.SubString(16), 
               ", nonce=", data_packet.nonce, ", sig_len=", data_packet.signature.size());
    
    // Get miner's public key from authenticated session
    std::vector<uint8_t> miner_pubkey = GetSessionPublicKey();
    if (miner_pubkey.empty()) {
        debug::error(FUNCTION, "No public key associated with session");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    // Verify Falcon signature
    LLC::FLKey flkey;
    if (!flkey.SetPubKey(miner_pubkey)) {
        debug::error(FUNCTION, "Invalid public key for session");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    std::vector<uint8_t> signed_data = data_packet.GetSignedData();
    if (!flkey.Verify(signed_data, data_packet.signature)) {
        debug::error(FUNCTION, "Falcon signature verification FAILED");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    debug::log(1, FUNCTION, "✓ Data Packet signature verified successfully");
    
    // Log miner attribution (for analytics, not stored on-chain)
    LogMinerAttribution(GetSessionKeyId(), data_packet.merkle_root, data_packet.nonce);
    
    // Process block submission normally (signature is now discarded)
    ProcessBlockSubmission(data_packet.merkle_root, data_packet.nonce);
    
    break;
}
```

### 4. Session Management

Add methods to track authenticated sessions:

```cpp
class MinerConnection
{
    // ... existing members ...
    
    /** Public key associated with authenticated session */
    std::vector<uint8_t> vchSessionPubKey;
    
    /** Session key ID (derived from public key hash) */
    uint256_t hashKeyId;
    
    /** Set session public key after successful authentication */
    void SetSessionPublicKey(const std::vector<uint8_t>& pubkey)
    {
        vchSessionPubKey = pubkey;
        // Derive keyId from pubkey hash for tracking
        hashKeyId = LLC::SK256(pubkey);
    }
    
    /** Get session public key */
    std::vector<uint8_t> GetSessionPublicKey() const
    {
        return vchSessionPubKey;
    }
    
    /** Get session key ID */
    uint256_t GetSessionKeyId() const
    {
        return hashKeyId;
    }
};
```

### 5. Miner Attribution Logging

Add optional logging for miner attribution (not stored in blockchain):

```cpp
/** 
 * Log miner attribution for analytics
 * This is stored in node logs/database for tracking, NOT in blockchain
 */
void LogMinerAttribution(const uint256_t& keyId, const uint512_t& merkleRoot, uint64_t nonce)
{
    // Example: Store in separate database or log file
    if (config::GetBoolArg("-logminerattribution", false))
    {
        debug::log(0, FUNCTION, "MINER_ATTRIBUTION: keyId=", keyId.SubString(16),
                   ", merkle=", merkleRoot.SubString(16), 
                   ", nonce=", nonce,
                   ", timestamp=", runtime::unifiedtimestamp());
        
        // Optional: Store in separate attribution database
        // AttributionDB::LogSubmission(keyId, merkleRoot, nonce, timestamp);
    }
}
```

### 6. Block Processing

The existing `ProcessBlockSubmission()` should work without changes:

```cpp
void ProcessBlockSubmission(const uint512_t& merkleRoot, uint64_t nonce)
{
    // Build block candidate from current template
    CBlock block = pCurrentBlock->GetBlock();
    block.hashMerkleRoot = merkleRoot;  // uint512 → uint1024 conversion
    block.nNonce = nonce;
    
    // Validate and submit to blockchain (normal flow)
    if (ValidateBlock(block))
    {
        SubmitToBlockchain(block);
        Respond(BLOCK_ACCEPTED);
    }
    else
    {
        Respond(BLOCK_REJECTED);
    }
}
```

**Important**: The signature is NOT passed to `ProcessBlockSubmission()` - it's already been verified and discarded.

### 7. Configuration Options

Add to `nexus.conf`:

```
# Enable/require Data Packet for authenticated miners
requireminerpacket=1        # 1 = require Data Packet, 0 = allow legacy SUBMIT_BLOCK

# Log miner attribution for analytics
logminerattribution=1       # 1 = log submissions, 0 = no logging
```

## Testing

### Test 1: Data Packet Deserialization

```cpp
void TestDataPacketDeserialization()
{
    // Build test packet
    std::vector<uint8_t> test_data;
    
    // Merkle root (64 bytes of 0xFF)
    test_data.insert(test_data.end(), 64, 0xFF);
    
    // Nonce: 0x0123456789ABCDEF (big-endian)
    test_data.push_back(0x01); test_data.push_back(0x23);
    test_data.push_back(0x45); test_data.push_back(0x67);
    test_data.push_back(0x89); test_data.push_back(0xAB);
    test_data.push_back(0xCD); test_data.push_back(0xEF);
    
    // Signature length: 0x0004 (4 bytes for testing)
    test_data.push_back(0x00); test_data.push_back(0x04);
    
    // Signature: 0xAABBCCDD
    test_data.push_back(0xAA); test_data.push_back(0xBB);
    test_data.push_back(0xCC); test_data.push_back(0xDD);
    
    // Deserialize
    DataPacket packet;
    assert(packet.Deserialize(test_data) == true);
    assert(packet.nonce == 0x0123456789ABCDEF);
    assert(packet.signature.size() == 4);
    assert(packet.signature[0] == 0xAA);
    
    printf("✓ Data Packet deserialization test passed\n");
}
```

### Test 2: Signature Verification

```cpp
void TestDataPacketSignatureVerification()
{
    // Generate test keypair
    LLC::FLKey key;
    key.MakeNewKey();
    
    auto pubkey = key.GetPubKey();
    auto privkey = key.GetPrivKey();
    
    // Create test data (merkle + nonce)
    std::vector<uint8_t> merkle_root(64, 0xAA);
    uint64_t nonce = 0x123456789ABCDEF0;
    
    std::vector<uint8_t> data_to_sign = merkle_root;
    for (int i = 7; i >= 0; --i) {
        data_to_sign.push_back((nonce >> (i * 8)) & 0xFF);
    }
    
    // Sign the data
    std::vector<uint8_t> signature;
    assert(key.Sign(data_to_sign, signature) == true);
    
    // Verify signature
    LLC::FLKey verify_key;
    verify_key.SetPubKey(pubkey);
    assert(verify_key.Verify(data_to_sign, signature) == true);
    
    printf("✓ Falcon signature verification test passed\n");
}
```

### Test 3: End-to-End Flow

1. Configure NexusMiner with Falcon keys
2. Start mining
3. Find a block
4. Verify SUBMIT_DATA_PACKET is sent (check NexusMiner logs)
5. Verify signature verification succeeds (check LLL-TAO logs)
6. Verify block is accepted
7. Verify signature is NOT in blockchain (check block data)

## Migration Path

### Phase 1: Optional Support (Recommended First Step)

```cpp
// Accept both SUBMIT_BLOCK and SUBMIT_DATA_PACKET
case SUBMIT_BLOCK:
    ProcessLegacyBlockSubmission();
    break;
    
case SUBMIT_DATA_PACKET:
    ProcessDataPacketSubmission();
    break;
```

**Config**: `requireminerpacket=0` (allow both)

### Phase 2: Encourage Data Packet

```cpp
// Prefer Data Packet but allow legacy
if (fMinerAuthenticated && opcode == SUBMIT_BLOCK) {
    debug::warning(FUNCTION, "Authenticated miner using legacy SUBMIT_BLOCK - recommend upgrade to SUBMIT_DATA_PACKET");
}
```

**Config**: `requireminerpacket=0` (allow both, warn on legacy)

### Phase 3: Require Data Packet

```cpp
// Reject legacy submissions from authenticated miners
if (fMinerAuthenticated && opcode == SUBMIT_BLOCK) {
    debug::error(FUNCTION, "Authenticated miner must use SUBMIT_DATA_PACKET");
    Respond(BLOCK_REJECTED);
    return;
}
```

**Config**: `requireminerpacket=1` (require Data Packet for authenticated miners)

## Example Implementation

### Complete Handler

```cpp
case SUBMIT_DATA_PACKET:
{
    // 1. Check authentication
    if (!fMinerAuthenticated) {
        debug::warning(FUNCTION, "SUBMIT_DATA_PACKET requires authentication");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    // 2. Deserialize packet
    DataPacket packet;
    if (!packet.Deserialize(INCOMING.DATA)) {
        debug::error(FUNCTION, "Invalid Data Packet format");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    debug::log(2, FUNCTION, "Data Packet received: merkle=", packet.merkle_root.SubString(16),
               ", nonce=", packet.nonce, ", sig_size=", packet.signature.size());
    
    // 3. Get session public key
    std::vector<uint8_t> pubkey = GetSessionPublicKey();
    if (pubkey.empty()) {
        debug::error(FUNCTION, "No public key for authenticated session");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    // 4. Verify signature
    LLC::FLKey flkey;
    if (!flkey.SetPubKey(pubkey)) {
        debug::error(FUNCTION, "Invalid session public key");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    std::vector<uint8_t> signed_data = packet.GetSignedData();
    if (!flkey.Verify(signed_data, packet.signature)) {
        debug::error(FUNCTION, "✗ Falcon signature verification FAILED");
        Respond(BLOCK_REJECTED);
        return;
    }
    
    debug::log(1, FUNCTION, "✓ Data Packet signature verified successfully");
    
    // 5. Log attribution (optional)
    if (config::GetBoolArg("-logminerattribution", false)) {
        LogMinerSubmission(GetSessionKeyId(), packet.merkle_root, packet.nonce);
    }
    
    // 6. Process block (signature is discarded - not stored on-chain)
    CBlock block = pCurrentBlock->GetBlock();
    block.hashMerkleRoot = packet.merkle_root;  // Note: may need type conversion
    block.nNonce = packet.nonce;
    
    if (ProcessBlock(block)) {
        debug::log(0, FUNCTION, "Block accepted from miner ", GetSessionKeyId().SubString(16));
        Respond(BLOCK_ACCEPTED);
    }
    else {
        debug::log(0, FUNCTION, "Block rejected (validation failed)");
        Respond(BLOCK_REJECTED);
    }
    
    break;
}
```

## Database Schema (Optional)

For tracking miner attribution:

```sql
CREATE TABLE miner_attribution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    key_id TEXT NOT NULL,           -- Hash of miner's public key
    merkle_root TEXT NOT NULL,      -- Block merkle root
    nonce INTEGER NOT NULL,         -- Solution nonce
    height INTEGER,                 -- Block height (if accepted)
    accepted BOOLEAN NOT NULL       -- Whether block was accepted
);

CREATE INDEX idx_miner_keyid ON miner_attribution(key_id);
CREATE INDEX idx_miner_timestamp ON miner_attribution(timestamp);
```

## Verification Checklist

Before deploying to production:

- [ ] SUBMIT_DATA_PACKET opcode added (value: 14)
- [ ] DataPacket deserializer implemented and tested
- [ ] Signature verification using FLKey::Verify()
- [ ] Session public key tracking functional
- [ ] Signature is NOT stored in blockchain
- [ ] Block processing works correctly after verification
- [ ] Attribution logging implemented (if desired)
- [ ] Configuration options work (requireminerpacket, logminerattribution)
- [ ] Backward compatibility maintained (SUBMIT_BLOCK still works)
- [ ] Error handling for invalid packets
- [ ] Security audit completed
- [ ] Integration tests passed with NexusMiner
- [ ] Documentation updated

## Security Audit Points

1. **Signature verification**: Always verify before accepting block
2. **Replay prevention**: Track submitted (merkle_root, nonce) pairs to prevent replay
3. **Public key validation**: Ensure pubkey is whitelisted (if using whitelist)
4. **Resource limits**: Limit signature size to prevent DoS (max ~2KB reasonable)
5. **Session validation**: Verify session is still active and authenticated

## Performance Considerations

### Expected Load

- **Signature verification**: ~0.5-1ms per block submission
- **CPU impact**: Negligible (Falcon is very fast)
- **Network bandwidth**: +~700 bytes per submission (acceptable for security benefit)
- **Database I/O**: Optional attribution logging adds minimal overhead

### Optimization Tips

1. **Cache public keys**: Store session pubkey in memory to avoid repeated lookups
2. **Parallel verification**: Verify signatures in separate thread if needed
3. **Batch logging**: Buffer attribution logs and write in batches
4. **Prune old attributions**: Delete attribution records older than N days

## Troubleshooting

### "Data Packet too small" error

**Cause**: Packet payload is less than 74 bytes  
**Solution**: Check NexusMiner is sending correct format, verify network transmission

### "Falcon signature verification FAILED"

**Cause**: Invalid signature, wrong public key, or data mismatch  
**Solution**: 
- Verify session public key is correct
- Check signed data matches received data
- Ensure NexusMiner and node use same endianness

### "No public key for authenticated session"

**Cause**: Session not properly initialized or expired  
**Solution**: Check authentication flow, ensure pubkey is stored during MINER_AUTH_RESULT

## References

- **NexusMiner Implementation**: `src/LLP/data_packet.hpp`, `src/protocol/src/protocol/solo.cpp`
- **Data Packet Spec**: `docs/data_packet.md`
- **Falcon Library**: `src/LLC/falcon/*`, `src/LLC/flkey.cpp`
- **Protocol Spec**: `docs/mining-llp-protocol.md`

## Support

For questions or issues with Data Packet integration:
- NexusMiner GitHub: https://github.com/Nexusoft/NexusMiner
- LLL-TAO GitHub: https://github.com/Nexusoft/LLL-TAO
- Nexus Telegram: https://t.me/NexusMiners

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-25  
**Author**: NexusMiner Development Team
