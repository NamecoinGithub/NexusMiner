# NodeSession - Unified Active Session Outer Wrapper

## Overview

NodeSession is a unified outer wrapper that manages dual-port connections (Stateless 9323 + Legacy 8323) to a single mining node. It presents a single authenticated identity to Worker_manager regardless of which port is active.

## Context & Motivation

The previous architecture managed authentication state inside `protocol::Solo` independently for each of the up to 4 connection legs:

```
Primary Node:   [Stateless Port 9323]  ←→  Solo instance #1  (session_id_A)
Primary Node:   [Legacy Port 8323]     ←→  Solo instance #2  (session_id_B)
Secondary Node: [Stateless Port 9323]  ←→  Solo instance #3  (session_id_C)  [failover/SIM only]
Secondary Node: [Legacy Port 8323]     ←→  Solo instance #4  (session_id_D)  [failover/SIM only]
```

However, the topology is physically constrained:
- If Primary Node goes down, **both** Primary ports die simultaneously
- If Secondary Node goes down, **both** Secondary ports die simultaneously
- There is no scenario where one port on a node survives while the other doesn't (absent misconfiguration)

The correct mental model is therefore **node-centric**, not port-centric:

```
┌─────────────────────────────────────┐   ┌─────────────────────────────────────┐
│         PRIMARY NODE                │   │        SECONDARY NODE (optional)    │
│                                     │   │                                     │
│  Port 9323 (Stateless)  ─┐          │   │  Port 9323 (Stateless)  ─┐          │
│                           ├─ NodeSession │                           ├─ NodeSession│
│  Port 8323 (Legacy)     ─┘          │   │  Port 8323 (Legacy)     ─┘          │
└─────────────────────────────────────┘   └─────────────────────────────────────┘
         Primary NodeSession                       Secondary NodeSession
```

## Design Principles

### 1. Outer Wrapper, Not Protocol Replacement

NodeSession wraps two Solo protocol instances and one SessionManager. It does **not** replace any existing auth logic; it simply coordinates between them.

### 2. OPCODE Firewall Preserved

Each Solo instance retains its `ProtocolLane`. The `packet.hpp` TX lane enforcement (`get_bytes(lane)`) is never bypassed. A Stateless-lane packet can only ever be sent on the 9323 connection; a Legacy-lane packet only on 8323.

### 3. Session ID is Node-Scoped

One Falcon handshake is performed per node. The resulting `session_id` is authoritative for that node. Both port connections on that node share the same logical session.

### 4. Simple Surface Area

Worker_manager calls:
- `NodeSession::connect()`
- `NodeSession::transmit()`
- `NodeSession::session_id()`
- `is_authenticated()`

Port selection is internal to NodeSession.

### 5. Failover Topology Correct

- `NodeSession primary` = Node A
- `NodeSession secondary` = Node B (optional)

If Node A goes down, both its ports die and the secondary NodeSession (Node B) takes over.

## Implementation

### File Structure

```
src/
├── node_session/
│   ├── inc/node_session/
│   │   └── node_session.hpp          ← new
│   └── src/node_session/
│       └── node_session.cpp          ← new
│   └── CMakeLists.txt                ← new
│   └── node_session_test.cpp         ← new
```

### Key Classes

#### NodeSession

**Location:** `src/node_session/inc/node_session/node_session.hpp`

**Purpose:** Unified wrapper for dual-port connections to a single mining node.

**Key Members:**
- `m_primary_connection` - Stateless port (9323) connection
- `m_secondary_connection` - Legacy port (8323) connection
- `m_primary_protocol` - Solo protocol instance for stateless port
- `m_secondary_protocol` - Solo protocol instance for legacy port
- `m_session_manager` - Shared session manager (one per node)
- `m_session_id` - Node-scoped session ID

**Key Methods:**
- `connect(endpoint, callback)` - Initiates connections to both ports
- `transmit(data)` - Transmits on active connection (primary first, fallback to secondary)
- `session_id()` - Returns the node's session ID
- `is_authenticated()` - Returns true if any connection is authenticated
- `request_work()` - Requests mining template
- `submit_block()` - Submits solved block

### Connection Flow

1. **Primary Connection (Stateless Port 9323)**
   - Connection initiated to primary endpoint
   - Protocol lane determined from port
   - Falcon authentication performed
   - Session ID assigned by node

2. **Secondary Connection (Legacy Port 8323)**
   - Initiated after primary connection succeeds
   - Only if SIM Link is enabled (`get_enable_sim_link()`)
   - Uses same node IP, different port (8323)
   - Independent authentication but same logical session

3. **Data Processing**
   - Each connection has its own RX accumulator
   - Packets extracted using `extract_packet_from_buffer_with_result()`
   - Protocol lane enforcement maintained
   - Processed through respective Solo instances

### Handler Registration

NodeSession provides a unified handler interface:

```cpp
// Template feed handler (called when new mining template received)
void set_template_handler(Template_handler handler);

// Block accepted handler (called when submitted block accepted)
void set_block_accepted_handler(Block_accepted_handler handler);

// Recovery handler (called when template staleness detected)
void set_recovery_initiated_handler(Recovery_handler handler);

// Session expired handler (called on session ID mismatch)
void set_session_expired_handler(Session_expired_handler handler);

// Session authenticated handler (called after MINER_AUTH_RESULT)
void set_session_authenticated_handler(Session_authenticated_handler handler);

// Session start handler (called on SESSION_START with keepalive interval)
void set_session_start_handler(Session_start_handler handler);

// Node shutdown handler (called when NODE_SHUTDOWN received from node)
void set_node_shutdown_handler(Node_shutdown_handler handler);
```

These handlers are registered with both Solo protocol instances internally, ensuring consistent behavior regardless of which port receives the event.

### Transmission Strategy

When `transmit()` is called:

1. Try primary connection first (if connected)
2. Fallback to secondary connection (if primary unavailable)
3. Log warning if no connections available
4. Return success/failure status

This provides automatic failover at the transmission level.

## Usage Example

```cpp
// Create NodeSession for primary node
auto primary_node = std::make_shared<NodeSession>(
    io_context,
    config,
    socket,
    stats_collector,
    "PRIMARY");

// Configure mining parameters
primary_node->set_miner_keys(pubkey, privkey);
primary_node->set_reward_address(reward_address);
primary_node->set_tritium_genesis(genesis);

// Register handlers
primary_node->set_template_handler([](const ::LLP::CBlock& block, uint32_t nBits) {
    // Feed template to workers
});

primary_node->set_session_authenticated_handler([](uint32_t session_id) {
    if (session_id == 0) {
        // Authentication failed - retry
    } else {
        // Authentication succeeded
    }
});

// Connect to node
primary_node->connect(node_endpoint, [](bool success) {
    if (success) {
        // Both ports connected and authenticated
        // Ready for mining
    }
});

// Request work
auto work_request = primary_node->request_work();
if (work_request) {
    primary_node->transmit(work_request);
}

// Submit solution
auto block_submission = primary_node->submit_block(block_data, nonce);
if (block_submission) {
    primary_node->transmit(block_submission);
}
```

## Benefits

### 1. Correct Topology Model
- Node-centric instead of port-centric
- Matches physical reality of network failures
- Simplifies failover logic

### 2. Unified Authentication
- Single session ID per node
- Consistent authentication state
- Reduced complexity in Worker_manager

### 3. Automatic Port Management
- Transparent dual-port operation
- Automatic fallback on transmission
- SIM Link configuration respected

### 4. Clean Abstraction
- Worker_manager doesn't need to know about ports
- Protocol lane enforcement preserved
- Existing Solo protocol logic unchanged

### 5. Simplified Failover
- Primary NodeSession = Node A
- Secondary NodeSession = Node B
- Clear failover semantics

## Future Enhancements

1. **Load Balancing**
   - Round-robin between ports
   - Latency-based port selection

2. **Health Monitoring**
   - Per-port health metrics
   - Automatic port switching on degradation

3. **Connection Pooling**
   - Multiple connections per port
   - Better throughput for high-hash operations

4. **Statistics**
   - Per-port bandwidth tracking
   - Authentication success rates
   - Template distribution metrics

## Testing

Unit tests are provided in `src/node_session/node_session_test.cpp`:

- NodeSession creation and initialization
- Configuration methods (keys, address, genesis)
- Handler registration
- Protocol instance access
- Stop and reset operations

To run tests:
```bash
cmake --build build/release --target node_session_test
ctest -R node_session_test
```

## Integration Status

**Current Status:** Design and implementation complete

**Next Steps:**
1. Integrate NodeSession into Worker_manager
2. Replace m_connection/m_secondary_connection with NodeSession instances
3. Update connect()/connect_secondary() to use NodeSession
4. Test with live mining node
5. Validate failover behavior

## References

- Design Issue: "NodeSession — Unified Active Session Outer Wrapper"
- Protocol Implementation: `src/protocol/inc/protocol/solo.hpp`
- Session Management: `src/protocol/inc/protocol/session_manager.hpp`
- Port Constants: `src/protocol_lane.hpp`
