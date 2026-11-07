#ifndef COMYC_ICE_COMMS_HPP
#define COMYC_ICE_COMMS_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace comyc::network::comms{

// STUN magic cookie
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN/TURN message types
// TURN is for when both the clients have symmetric NAT (hole-punching not possible)
enum class IceMessageType : uint16_t{
    BINDING_REQUEST      = 0x0001,
    BINDING_RESPONSE     = 0x0101,
    BINDING_ERROR_RESP   = 0x0111,
    
    // TURN Specific Messages
    ALLOCATE_REQUEST     = 0x0003,
    ALLOCATE_RESPONSE    = 0x0103,
    ALLOCATE_ERROR_RESP  = 0x0113,
    REFRESH_REQUEST      = 0x0004,
    REFRESH_RESPONSE     = 0x0104,
    DATA_INDICATION      = 0x0017,
    SEND_INDICATION      = 0x0016
};

// STUN/TURN attribute types
enum class IceAttributeType: uint16_t{
    MAPPED_ADDRESS     = 0x0001,
    XOR_MAPPED_ADDRESS = 0x0020,
    USERNAME           = 0x0006,
    MESSAGE_INTEGRITY  = 0x0008,
    ERROR_CODE         = 0x0009,
    UNKNOWN_ATTRIBUTES = 0x000A,
    LIFETIME           = 0x000D,
    XOR_PEER_ADDRESS   = 0x012A,
    DATA               = 0x0113,
    XOR_RELAY_ADDRESS  = 0x0116
};

#pragma pack(push, 1) // To prevent padding of struct members by the compiler, which would result unwanted sizes
// Standard 20-byte STUN message header
struct StunHeader{
    uint16_t msg_type;
    uint16_t msg_len;
    uint32_t magic_cookie;
    uint8_t transaction_id[12]; // 96-bit unique identifier for matching request/response
};

// Generic TLV attribute header
struct StunAttributeHeader{
    uint16_t type;
    uint16_t length;
};

// Raw IPv4 mapped address payload
struct StunMappedAddressHeader{
    uint8_t reserved;   // always 0x00
    uint8_t family;     // 0x01 => IPv4, 0x02 => IPv6
    uint16_t port;      // port number
    uint32_t address;   // IPv4 address in network byte order
};
#pragma pack(pop) // From here on out, there will be normal padding

// Helper structure for parser ICE attributes
struct IceAttribute{
    IceAttributeType type;
    std::vector<uint8_t> value;
};

// Encapsulates a completely constructed STUN/TURN packet
class IcePacket{
public:
    StunHeader header{};
    std::vector<IceAttribute> attributes;

    IcePacket(){
        header.magic_cookie = htonl(STUN_MAGIC_COOKIE);
        std::memset(header.transaction_id, 0, sizeof(header.transaction_id));
    }

    // Set message type using enum
    void set_type(IceMessageType type){
        header.msg_type = htons(static_cast<uint16_t>(type));
    }

    // Get message type enum
    IceMessageType get_type() const{
        return static_cast<IceMessageType>(ntohs(header.msg_type));
    }

    // Set a 12-byte raw transaction ID
    void set_transaction_id(const uint8_t id[12]){
        std::memcpy(header.transaction_id, id, 12);
    }

    // Add an attribute to the packet
    void add_attribute(IceAttributeType type, const std::vector<uint8_t>& val){
        attributes.push_back({type, val});
    }

    // Add an XOR-MAPPED-ADDRESS attribute 
    void add_xor_mapped_address(const std::string& ip, uint16_t port){
        StunMappedAddressHeader addr_hdr{};
        addr_hdr.reserved = 0x00;
        addr_hdr.family = 0x01; // IPv4

        // XOR port with most significant 16 bits of magic cookie
        uint16_t xor_port = port ^ (STUN_MAGIC_COOKIE >> 16);
        addr_hdr.port = htons(xor_port);

        // XOR IPv4 address with magic cookie
        in_addr net_ip{};
        inet_pton(AF_INET, ip.c_str(), &net_ip);
        addr_hdr.address = net_ip.s_addr ^ htonl(STUN_MAGIC_COOKIE);

        std::vector<uint8_t> val(sizeof(StunMappedAddressHeader));
        std::memcpy(val.data(), &addr_hdr, sizeof(addr_hdr));

        add_attribute(IceAttributeType::XOR_MAPPED_ADDRESS, val);
    }

    // Seralize packet into binary bytes ready for UDP transaction
    std::vector<uint8_t> serialize() const{
        std::vector<uint8_t> buffer;

        // Reserve space for body calculation
        size_t body_len = 0;
        for(const auto& attr: attributes){
            body_len += sizeof(StunAttributeHeader) + attr.value.size();
            // attributes are padded to 4-byte alignemts
            size_t pad = (4 - (attr.value.size() % 4)) % 4;
            body_len += pad;
        }

        StunHeader output_header = header;
        output_header.msg_len = htons(static_cast<uint16_t>(body_len));

        // append header
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&output_header);
        buffer.insert(buffer.end(), hdr_ptr, hdr_ptr + sizeof(StunHeader));

        // append attributes
        for(const auto& attr : attributes){
            StunAttributeHeader attr_hdr{};
            attr_hdr.type = htons(static_cast<uint16_t>(attr.type));
            attr_hdr.length = htons(static_cast<uint16_t>(attr.value.size()));

            const uint8_t* attr_ptr = reinterpret_cast<const uint8_t*>(&attr_hdr);
            buffer.insert(buffer.end(), attr_ptr, attr_ptr+sizeof(StunAttributeHeader));
            buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());

            // 32-bit alignment
            size_t pad = (4 - (attr.value.size() % 4)) % 4;
            for(size_t i=0; i<pad; i++){
                buffer.push_back(0x00);
            }
        }

        return buffer;
    }

    // parse incoming raw UDP byte array into an IcePacket struct
    static bool deserialize(const uint8_t* data, size_t len, IcePacket& out_packet){
        if(len < sizeof(StunHeader)) return false;

        std::memcpy(&out_packet.header, data, sizeof(StunHeader));

        // check magic cookie
        if(ntohl(out_packet.header.magic_cookie) != STUN_MAGIC_COOKIE){
            return false;
        }

        uint16_t payload_len = ntohs(out_packet.header.msg_len);
        if(len < sizeof(StunHeader)+payload_len) return false;

        out_packet.attributes.clear();
        size_t offset = sizeof(StunHeader);

        while(offset + sizeof(StunAttributeHeader) <= sizeof(StunHeader) + payload_len){
            StunAttributeHeader attr_hdr{};
            std::memcpy(&attr_hdr, data+offset, sizeof(StunAttributeHeader));

            uint16_t attr_type = ntohs(attr_hdr.type);
            uint16_t attr_len = ntohs(attr_hdr.length);

            offset += sizeof(StunAttributeHeader);
            if(offset+attr_len > len) return false;

            std::vector<uint8_t> val(data+offset, data+offset+attr_len);
            out_packet.attributes.push_back({static_cast<IceAttributeType>(attr_type), val});

            // 4-byte alignment
            size_t pad = (4 - (attr_len % 4)) % 4;
            offset += attr_len + pad;
        }

        return true;
    }
};

}

#endif // COMYC_ICE_COMMS_HPP