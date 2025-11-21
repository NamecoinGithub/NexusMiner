#ifndef NEXUSMINER_PROTOCOL_PROTOCOL_HPP
#define NEXUSMINER_PROTOCOL_PROTOCOL_HPP

#include "network/types.hpp"
#include "packet.hpp"
#include "block.hpp"
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>

namespace nexusminer {
namespace network { class Connection; }
namespace protocol
{

// Compact Block header layout (matching LLL-TAO BLOCK_DATA for stateless miner):
//  - 0..3:   nVersion (4 bytes)
//  - 4..35:  hashPrevBlock (32 bytes)
//  - 36..67: hashMerkleRoot (32 bytes)
//  - 68..71: nChannel (4)
//  - 72..75: nHeight (4)
//  - 76..79: nBits (4)
//  - 80..87: nNonce (8)
//  - 88..91: nTime (4)
constexpr std::size_t MIN_BLOCK_HEADER_SIZE =
      4  // nVersion
    + 32 // hashPrevBlock
    + 32 // hashMerkleRoot
    + 4  // nChannel
    + 4  // nHeight
    + 4  // nBits
    + 8  // nNonce
    + 4; // nTime

class Protocol {
public:

    using Login_handler = std::function<void(bool login_result)>;
    using Set_block_handler = std::function<void(::LLP::CBlock block, std::uint32_t nBits)>;

    virtual ~Protocol() = default;

    virtual void reset() = 0;
    virtual network::Shared_payload login(Login_handler handler) = 0;
    virtual network::Shared_payload get_work() = 0;
    virtual network::Shared_payload submit_block(std::vector<std::uint8_t> const& block_data, std::uint64_t nonce ) = 0;

    virtual void process_messages(Packet packet, std::shared_ptr<network::Connection> connection) = 0;
    virtual void set_block_handler(Set_block_handler handler) = 0;
};

}
}
#endif