#include "protocol/packet_builder.hpp"
#include "packet.hpp"
#include "miner_opcodes.hpp"

namespace nexusminer {
namespace protocol {

network::Shared_payload PacketBuilder::build(ProtocolLane lane, uint8_t legacy_opcode)
{
    if (lane == ProtocolLane::STATELESS) {
        Packet pkt{ static_cast<uint16_t>(LLP::MirrorOpcode(legacy_opcode)) };
        return pkt.get_bytes();
    } else {
        Packet pkt{ static_cast<uint8_t>(legacy_opcode) };
        return pkt.get_bytes();
    }
}

network::Shared_payload PacketBuilder::build(ProtocolLane lane, uint8_t legacy_opcode,
                                              const std::vector<uint8_t>& payload)
{
    auto data = std::make_shared<network::Payload>(payload);
    if (lane == ProtocolLane::STATELESS) {
        Packet pkt{ static_cast<uint16_t>(LLP::MirrorOpcode(legacy_opcode)), data };
        return pkt.get_bytes();
    } else {
        Packet pkt{ static_cast<uint8_t>(legacy_opcode), data };
        return pkt.get_bytes();
    }
}

} // namespace protocol
} // namespace nexusminer
