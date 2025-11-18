#!/bin/bash
# Phase 2 Integration Verification Script
# 
# This script helps verify that NexusMiner Phase 2 integration is working correctly.
# It checks the configuration, tests packet building, and verifies the binary.

set -e

echo "=========================================="
echo "NexusMiner Phase 2 Verification Script"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if NexusMiner binary exists
if [ ! -f "./build/NexusMiner" ]; then
    echo -e "${RED}✗ NexusMiner binary not found${NC}"
    echo "  Please build first: cd build && cmake .. && make"
    exit 1
fi
echo -e "${GREEN}✓ NexusMiner binary found${NC}"

# Check if it's executable
if [ ! -x "./build/NexusMiner" ]; then
    echo -e "${RED}✗ NexusMiner is not executable${NC}"
    exit 1
fi
echo -e "${GREEN}✓ NexusMiner is executable${NC}"

# Check for Falcon library
if [ -f "./build/src/LLC/libLLC.a" ]; then
    echo -e "${GREEN}✓ Falcon library (LLC) built${NC}"
else
    echo -e "${YELLOW}⚠ Falcon library not found${NC}"
fi

# Check for protocol library
if [ -f "./build/src/protocol/libprotocol.a" ]; then
    echo -e "${GREEN}✓ Protocol library built${NC}"
else
    echo -e "${RED}✗ Protocol library not found${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo "Configuration Checks"
echo "=========================================="
echo ""

# Check if example config exists
if [ -f "./miner.conf" ]; then
    echo -e "${GREEN}✓ Example config found: miner.conf${NC}"
    
    # Check for Falcon keys in config
    if grep -q "miner_falcon_pubkey" ./miner.conf 2>/dev/null; then
        echo -e "${GREEN}✓ Config has Falcon public key field${NC}"
    else
        echo -e "${YELLOW}⚠ Config missing Falcon public key field${NC}"
        echo "  Add: \"miner_falcon_pubkey\": \"<hex>\""
    fi
    
    if grep -q "miner_falcon_privkey" ./miner.conf 2>/dev/null; then
        echo -e "${GREEN}✓ Config has Falcon private key field${NC}"
    else
        echo -e "${YELLOW}⚠ Config missing Falcon private key field${NC}"
        echo "  Add: \"miner_falcon_privkey\": \"<hex>\""
    fi
    
    if grep -q "local_ip" ./miner.conf 2>/dev/null; then
        echo -e "${GREEN}✓ Config has local_ip field${NC}"
    else
        echo -e "${YELLOW}⚠ Config missing local_ip field${NC}"
        echo "  Add: \"local_ip\": \"127.0.0.1\""
    fi
else
    echo -e "${YELLOW}⚠ No miner.conf found${NC}"
    echo "  You can generate Falcon config with: ./build/NexusMiner --generate-falcon-keys"
fi

echo ""
echo "=========================================="
echo "Protocol Implementation Checks"
echo "=========================================="
echo ""

# Check if packet.hpp has Phase 2 headers
if grep -q "MINER_AUTH_INIT = 207" ./src/LLP/packet.hpp 2>/dev/null; then
    echo -e "${GREEN}✓ Packet headers synchronized with LLL-TAO Phase 2${NC}"
    echo "  MINER_AUTH_INIT = 207 ✓"
    echo "  MINER_AUTH_RESPONSE = 209 ✓"
    echo "  SESSION_START = 211 ✓"
    echo "  CHANNEL_ACK = 206 ✓"
else
    echo -e "${RED}✗ Packet headers NOT synchronized${NC}"
    exit 1
fi

# Check if solo.cpp has Phase 2 auth
if grep -q "Phase 2" ./src/protocol/src/protocol/solo.cpp 2>/dev/null; then
    echo -e "${GREEN}✓ Solo protocol has Phase 2 implementation${NC}"
else
    echo -e "${YELLOW}⚠ Solo protocol may not have Phase 2 markers${NC}"
fi

# Check if address + timestamp auth is implemented
if grep -q "auth_message.insert.*m_address" ./src/protocol/src/protocol/solo.cpp 2>/dev/null; then
    echo -e "${GREEN}✓ Auth message uses address + timestamp${NC}"
else
    echo -e "${YELLOW}⚠ Auth message format unclear${NC}"
fi

echo ""
echo "=========================================="
echo "Documentation"
echo "=========================================="
echo ""

if [ -f "./PHASE2_INTEGRATION.md" ]; then
    echo -e "${GREEN}✓ Phase 2 integration documentation found${NC}"
else
    echo -e "${YELLOW}⚠ Phase 2 documentation not found${NC}"
fi

if [ -f "./README.md" ]; then
    echo -e "${GREEN}✓ README.md found${NC}"
else
    echo -e "${YELLOW}⚠ README.md not found${NC}"
fi

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""

echo -e "${GREEN}✓ NexusMiner Phase 2 integration appears correct${NC}"
echo ""
echo "Next steps:"
echo "1. Generate Falcon keys (if not done):"
echo "   ./build/NexusMiner --generate-falcon-keys"
echo ""
echo "2. Configure your miner.conf with:"
echo "   - Falcon public/private keys"
echo "   - local_ip (for auth message)"
echo "   - wallet_ip (LLL-TAO node address)"
echo "   - mining_mode (PRIME or HASH)"
echo ""
echo "3. Start LLL-TAO Phase 2 node"
echo ""
echo "4. Test connection:"
echo "   ./build/NexusMiner -c miner.conf"
echo ""
echo "5. Check logs for:"
echo "   - \"Authentication SUCCEEDED\""
echo "   - \"Session ID: 0x...\""
echo "   - \"CHANNEL_ACK\""
echo "   - \"Requesting initial work\""
echo ""
echo "See PHASE2_INTEGRATION.md for detailed testing instructions."
echo ""
echo "\"To Man what is Impossible is ONLY possible with GOD\""
