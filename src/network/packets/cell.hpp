#pragma once
#include <type_traits>
#include <variant>
#include <array>


enum class PayloadTier : uint8_t{
    TIER_64   = 0,
    TIER_128  = 1,
    TIER_512  = 2,
    TIER_1024 = 3
};


enum class RoutingFlag : uint8_t{
    CLIENT_TO_RELAY = 0,
    RELAY_TO_EXIT   = 1,
    EXIT_TO_RELAY   = 2,
    RELAY_TO_CLIENT = 3,
    INVALID         = 4
};


// // this macro might lead to deadly bugs and performance inefficiencies later on
// // #pragma pack(push, 1)       // ? START: Tell compiler not to optimize this to 2^n bytes using padding

using session_id_t = uint32_t;
using circuit_id_t = uint64_t;
using sequence_id_t = uint64_t;

/*
Rules to follow:
1. if the struct size isn't a multiple of its largest member's alignment requirement (usually 4 or 8), compilers insert trailing padding bytes to align elements in an array of structs.
2. place 8-byte integers on offsets divisible by 8, 4-byte integers on offsets divisible by 4, and 2-byte integers on offsets divisible by 2.
3. never use int, long, short, or size_t. Always use <cstdint> types (uint8_t, uint16_t, uint32_t, uint64_t).
*/


struct TransitHeader{
    // Total 16 Bytes
    circuit_id_t circuit_id;  // 8 Bytes: Circuit ID, each (client app -> exit) connection has a circuit id
    uint16_t frame_len;       // 2 Bytes: The size of the PayloadHeader + payload
    uint16_t flags;           // 2 Bytes: Define later on.
    PayloadTier payload_tier; // 1 Byte: Tier (fixed size) of the useful packet at exit, the size of PayloadHeader + (Payload + Padding).
    uint8_t _reserved_[3];    // 3 Bytes reserved for future expansion
};


struct PayloadHeader{
    // Total 16 Bytes
    sequence_id_t sequence_id; // 8 Bytes: Sequence ID, each Circuit ID uses a Sequence ID, for reordering at exit etc.
    uint16_t ip_protocol;      // 2 Bytes: Identifies the protocol which the underlying client packet follows (like the 4 byte header mac prepends in utun)
    uint16_t packet_id;        // 2 Bytes: If the packet which is being sent is too large, we split it into many different packets. To distinguish from differnt large packets, we have packet_id
    uint16_t payload_len;      // 2 Bytes: Actual payload bytes in this cell.
    uint8_t frag_index;        // 1 Byte: Index of this fragment in the huge packet.
    uint8_t frag_total;        // 1 Byte: Total number of fragments made from the huge packet.
};


static_assert(sizeof(TransitHeader) == 16, "TransitHeader layout broken");
static_assert(sizeof(PayloadHeader) == 16, "PayloadHeader layout broken");

static_assert(std::is_trivially_copyable_v<TransitHeader>, "TransitHeader is not memcpy safe");
static_assert(std::is_trivially_copyable_v<PayloadHeader>, "PayloadHeader is not memcpy safe");

constexpr size_t TRANSIT_HDR_SZ = sizeof(TransitHeader);
constexpr size_t PAYLOAD_HDR_SZ = sizeof(PayloadHeader);
constexpr size_t FAMILY_HDR_UTUN_SZ = sizeof(uint32_t);

// // #pragma pack(pop)           // ? END


using PayloadBuffer = std::variant<
    std::array<uint8_t, 64>,
    std::array<uint8_t, 128>,
    std::array<uint8_t, 512>,
    std::array<uint8_t, 1024>
>;


using ExitBoundBuffer = std::variant<
    std::array<uint8_t, 64 + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 128 + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 512 + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 1024 + PAYLOAD_HDR_SZ>
>;


using RelayBoundBuffer = std::variant<
    std::array<uint8_t, 64 + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 128 + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 512 + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ>,
    std::array<uint8_t, 1024 + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ>
>;


struct RelayBoundCell{
    RoutingFlag route_flag;
    session_id_t session_id;        // 4 Bytes: for client and relays to figure out which shared key to use if they are connected in multiple circuits
    RelayBoundBuffer tphdr_payload; // TransitHeader + PayloadHeader + app data aka InnerCell
};


// struct ExitBoundCell{
//     TransitHeader thdr;
//     ExitBoundBuffer phdr_payload;   // PayloadHeader + app data aka RawCell
// };


struct ExitFullCell{
    RoutingFlag route_flag;
    TransitHeader thdr;
    PayloadHeader phdr;
    PayloadBuffer payload; // app data
};


struct ClientFullCell{
    RoutingFlag route_flag;
    session_id_t session_id; // unencrypted
    TransitHeader thdr;      // encrypted using SH_CR
    PayloadHeader phdr;      // encrypted using SH_CR(SH_CE)
    PayloadBuffer payload;   // encrypted using SH_CR(SH_CE)
};


struct ClientFullHeaders{
    RoutingFlag route_flag;
    session_id_t session_id;
    TransitHeader thdr;
    PayloadHeader phdr;
};