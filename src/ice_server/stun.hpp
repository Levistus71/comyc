#ifndef COMYC_ICE_SERVER_STUN_HPP
#define COMYC_ICE_SERVER_STUN_HPP

#include <vector>
#include <iostream>
#include <cstdint>
#include "../network/sockets/udp_sock.hpp"
#include "../network/comms/ice_comms.hpp"

namespace comyc::ice_server{
using namespace comyc::network::sockets;
using namespace comyc::network::comms;

class StunServer{
public:
    StunServer() = default;
    ~StunServer() = default;

    // process and incoming raw STUN packet and generate a response
    // returns true if a response packet was successfully constructed
    bool process_packet(const uint8_t* raw_data, size_t length, const Endpoint& client_ep, std::vector<uint8_t>& out_response){
        IcePacket request_pkt;

        // 1. deserialise and validate the STUN header
        if(!IcePacket::deserialize(raw_data, length, request_pkt)){
            return false; // invalid packet/magic cookie => drop packet
        }

        // 2. validate message type (must be BINDING_REQUEST)
        if(request_pkt.get_type() != IceMessageType::BINDING_REQUEST){
            out_response = create_error_response(request_pkt, 400);
            return true; // why return true? => because the error response is a valid response
        }

        // 3. construct BINDING_RESPONSE
        IcePacket response_pkt;
        response_pkt.set_type(IceMessageType::BINDING_RESPONSE);

        // preserve exact transaction ID from request
        response_pkt.set_transaction_id(request_pkt.header.transaction_id);

        // 4. add XOR-mapped addr with the client's public endpoint
        response_pkt.add_xor_mapped_address(client_ep.ip, client_ep.port);

        // 5. serialise response into output buffer
        out_response = response_pkt.serialize();
        return true;
    }

private:
    // helper to construct a standard STUN error response
    std::vector<uint8_t> create_error_response(const IcePacket& req_pkt, uint16_t error_code_num){
        IcePacket err_pkt;
        err_pkt.set_type(IceMessageType::BINDING_ERROR_RESP);
        err_pkt.set_transaction_id(req_pkt.header.transaction_id);

        // ERROR-CODE format: 2bytes reserved, 1byte error_class, 1byte error_number
        uint8_t error_class = static_cast<uint8_t>(error_code_num/100);
        uint8_t error_number = static_cast<uint8_t>(error_code_num%100);

        std::vector<uint8_t> err_attr_val = {0x00, 0x00, error_class, error_number};
        err_pkt.add_attribute(IceAttributesType::ERROR_CODE, err_attr_val);

        return err_pkt.serialize();
    }
};

} // namespace comyc::ice_server

#endif // COMYC_ICE_SERVER_STUN_HPP