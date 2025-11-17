# Falcon Miner Authentication for NexusMiner

This document describes how to use Falcon-based stateless miner authentication with NexusMiner SOLO mode.

## Overview

Falcon miner authentication provides a quantum-resistant, session-independent way for miners to authenticate with Nexus LLL-TAO nodes. This eliminates the dependency on TAO::API sessions and provides stronger security for mining operations.

## Prerequisites

- NexusMiner with Falcon authentication support
- Nexus LLL-TAO node with MINER_AUTH opcodes support
- Falcon crypto library (currently stub implementation for testing)

## Generating Miner Keys

To generate a new Falcon-512 keypair for your miner:

```bash
./NexusMiner --create-keys
```

This will output:
- A public key (safe to share with node operators)
- A private key (MUST be kept secret!)
- Ready-to-paste configuration snippets for both miner.conf and nexus.conf

**Security Warning:** The private key must be kept secret and secure. Anyone with access to your private key can impersonate your miner.

## Configuring NexusMiner

Add the following to your `miner.conf` (using the keys generated above):

```json
{
    "version": 1,
    "wallet_ip": "127.0.0.1",
    "port": 8325,
    "mining_mode": "PRIME",
    "miner_falcon_pubkey": "<your_public_key_hex>",
    "miner_falcon_privkey": "<your_private_key_hex>",
    ...
}
```

The `miner_falcon_pubkey` and `miner_falcon_privkey` fields are optional. If not provided, NexusMiner will use legacy authentication (SET_CHANNEL only).

## Configuring Nexus Node

The node operator must whitelist your public key in `nexus.conf`:

```
-minerallowkey=<your_public_key_hex>
```

## Authentication Handshake Protocol

When Falcon keys are configured, NexusMiner performs the following handshake:

1. **MINER_AUTH_INIT**: Miner sends public key to node
2. **MINER_AUTH_CHALLENGE**: Node generates and sends a 32-byte nonce
3. **MINER_AUTH_RESPONSE**: Miner signs the nonce with private key and sends signature
4. **MINER_AUTH_RESULT**: Node verifies signature and sends success/failure
5. **SET_CHANNEL**: If authenticated, miner sends SET_CHANNEL to start mining

If authentication fails, mining will not proceed.

## Logs

When Falcon authentication is enabled, you'll see logs like:

```
[Solo] Starting Falcon miner authentication handshake
[Solo] Sending MINER_AUTH_INIT with public key (897 bytes)
[Solo] Received MINER_AUTH_CHALLENGE from node
[Solo] Sending MINER_AUTH_RESPONSE with signature (690 bytes)
[Solo] ✓ Miner authentication SUCCEEDED
[Solo] Now sending SET_CHANNEL channel=1 (prime)
```

## Backward Compatibility

Falcon authentication is fully backward compatible:
- If no Falcon keys are configured, NexusMiner uses legacy authentication
- Nodes without MINER_AUTH support will work with non-authenticated miners
- The authentication is optional and can be enabled/disabled via configuration

## Current Limitations

**Note**: The current implementation uses a STUB Falcon crypto library for protocol testing. The actual Falcon-512 library from Nexus LLL-TAO needs to be integrated for production use.

Key sizes:
- Public key: 897 bytes (Falcon-512)
- Private key: 1281 bytes (Falcon-512)
- Signature: ~690 bytes (variable)

## Troubleshooting

### Authentication Failed

If you see `✗ Miner authentication FAILED`:
- Verify your public key is correctly whitelisted on the node
- Ensure your keys in miner.conf match what was generated
- Check that the keys are valid hex strings
- Verify the node has MINER_AUTH support enabled

### No Falcon Keys Configured

If you see `No Falcon keys configured, using legacy authentication`:
- This is normal if you haven't added the Falcon key fields to miner.conf
- Legacy authentication (SET_CHANNEL only) will be used
- To enable Falcon auth, generate keys with `--create-keys` and add to config

## Example Configuration

Here's a complete miner.conf example with Falcon authentication:

```json
{
    "version": 1,
    "wallet_ip": "127.0.0.1",
    "port": 8325,
    "local_ip": "127.0.0.1",
    "mining_mode": "PRIME",
    "miner_falcon_pubkey": "e8c7cd6100709a1c5692640273d3f1d1f7b0b6f25e209174b3d31d01f90413e5...",
    "miner_falcon_privkey": "c27d216a58ae870d9515b30d412d0d1fdb2b7a0f25aa19e44dbe629ccfc1e546...",
    "connection_retry_interval": 5,
    "get_height_interval": 2,
    "ping_interval": 10,
    "log_level": 2,
    "logfile": "miner.log",
    "stats_printers": [
        {
            "stats_printer": {
                "mode": "console"
            }
        }
    ],
    "print_statistics_interval": 10,
    "workers": [
        {
            "worker": {
                "id": "myWorker0",
                "mode": {
                    "hardware": "cpu"
                }
            }
        }
    ]
}
```
