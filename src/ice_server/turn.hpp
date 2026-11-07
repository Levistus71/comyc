#ifndef COMYC_ICE_SERVER_TURN_HPP
#define COMYC_ICE_SERVER_TURN_HPP

#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <cstdint>
#include <iostream>
#include "../network/sockets/udp_sock.hpp"
#include "../network/comms/ice_comms.hpp"

namespace comyc::ice_server{

using namespace comyc::network::sockets;
using namespace comyc::network::comms;

// represents an active relay allocation for a TURN clietn
struct TurnAllocation{
    std::string allocation_id;
    Endpoint client_ep; // client's original public endpoint
    std::unique_ptr<UdpSocket> relay_sock;  // dedicated UDP socket for realying traffic
    uint16_t relay_port{0};
    std::chrono::steady_clock::time_point expires_at; // duration of connection with the TURN server
};

class TurnServer{
private:
    std::string server_public_ip_;
    // map client ip:port string key to active allocation
    std::unordered_map<std::string, TurnAllocation> allocations_;

    std::string make_client_key(const Endpoint& ep) const{
        return ep.ip + ":" + std::to_string(ep.port);
    }
public:
    explicit TurnServer(std::string public_ip = "127.0.0.1")
        : server_public_ip_(std::move(public_ip)) {}

    ~TurnServer() = default;

    // process an incoming TURN packet from a registered or new client
    bool process_packet(const uint8_t* raw_data, 
                        size_t length, 
                        const Endpoint& client_ep, 
                        std::vector<uint8_t>& out_response, //! what does this represent? => allocate/response
                        Endpoint& out_forward_dest, 
                        std::vector<uint8_t>& out_forward_payload){
        IcePacket request_pkt;
        if(!IcePacket::deserialize(raw_data, length, request_pkt)){
            return false;
        }

        IceMessageType msg_type = request_pkt.get_type();

        switch(msg_type){
            case IceMessageType::ALLOCATE_REQUEST:
                return handle_allocate(request_pkt, client_ep, out_response);

            case IceMessageType::REFRESH_REQUEST:
                return handle_refresh(request_pkt, client_ep, out_response);

            case IceMessageType::SEND_INDICATION:
                return handle_send_indication(request_pkt, client_ep, out_forward_dest, out_forward_payload);

            default:
                // unsupported TURN message type
                return false;
        }
    }

    // wrap raw datagram received on a relay socket into a DATA_INDICATION for the TURN client
    std::vector<uint8_t> build_data_indication(const Endpoint& peer_ep,
                                                const uint8_t* data,
                                                size_t len){
        IcePacket pkt;
        pkt.set_type(IceMessageType::DATA_INDICATION);

        // add XOR-PEER-ADDRESS attribure
        pkt.add_xor_mapped_address(peer_ep.ip, peer_ep.port);

        // add DATA attribute containing the raw payload
        std::vector<uint8_t> payload(data, data+len);
        pkt.add_attribute(IceAttributeType::DATA, payload);

        return pkt.serialize();
    }

    void purge_expired_allocations(){
        auto now = std::chrono::steady_clock::now();
        for(auto it = allocations_.begin(); it!=allocations_.end(); ){
            if(it->second.expires_at <= now){
                it = allocations_.erase(it);
            }
            else{
                ++it;
            }
        }
    }

private:
    // handle ALLOCATE_REQUEST: binds dynamic UDP relay socket and return XOR-RELAY-ADDRESS
    bool handle_allocate(const IcePacket& req_pkt,
                         const Endpoint& client_ep,
                         std::vector<uint8_t>& out_response){
        std::string client_key = make_client_key(client_ep);

        auto relay_sock = std::make_unique<UdpSocket>();
        if(!relay_sock->open() || !relay_sock->bind(0)){
            return false;
        }

        uint16_t allocated_port = relay_sock->get_local_port();

        TurnAllocation alloc;
        alloc.allocation_id = client_key;
        alloc.client_ep = client_ep;
        alloc.relay_sock = std::move(relay_sock);
        alloc.relay_port = allocated_port;
        // set default lifetime to 600s
        alloc.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(600);
        allocations_[client_key] = std::move(alloc);

        // build ALLOCATE_RESPONSE
        IcePacket resp_pkt;
        resp_pkt.set_type(IceMessageType::ALLOCATE_RESPONSE);
        resp_pkt.set_transaction_id(req_pkt.header.transaction_id);

        // add XOR-RELAY-ADDRESS attribute
        resp_pkt.add_xor_mapped_address(server_public_ip_, allocated_port);

        // add LIFETIME attribute (600s)
        uint32_t lifetime = htonl(600);
        std::vector<uint8_t> lifetime_bytes(4);
        std::memcpy(lifetime_bytes.data(), &lifetime, 4);
        resp_pkt.add_attribute(IceAttributeType::LIFETIME, lifetime_bytes);

        out_response = resp_pkt.serialize();
        return true;
    }

    // handle REFRESH_REQUEST: extends allocation expiration time
    bool handle_refresh(const IcePacket& req_pkt,
                        const Endpoint& client_ep,
                        std::vector<uint8_t>& out_response){
        std::string client_key = make_client_key(client_ep);
        auto it = allocations_.find(client_key);

        if(it == allocations_.end()){
            return false;
        }

        // extend allocation lifetime by 600s
        it->second.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(600);

        IcePacket resp_pkt;
        resp_pkt.set_type(IceMessageType::REFRESH_RESPONSE);
        resp_pkt.set_transaction_id(req_pkt.header.transaction_id);

        uint32_t lifetime = htonl(600);
        std::vector<uint8_t> lifetime_bytes(4);
        std::memcpy(lifetime_bytes.data(), &lifetime, 4);
        resp_pkt.add_attribute(IceAttributeType::LIFETIME, lifetime_bytes);

        out_response = resp_pkt.serialize();
        return true;
    }

    bool handle_send_indication(const IcePacket& req_pkt,
                                const Endpoint& client_ep,
                                Endpoint& out_dest_ep,
                                std::vector<uint8_t>& out_payload){
        std::string client_key = make_client_key(client_ep);
        if(allocations_.find(client_key) == allocations_.end()){
            return false;
        }

        bool found_peer = false;
        bool found_data = false;

        for(const auto& attr: req_pkt.attributes){
            if(attr.type == IceAttributeType::XOR_MAPPED_ADDRESS ||
               attr.type == IceAttributeType::XOR_PEER_ADDRESS){
                if(attr.value.size() >= sizeof(StunMappedAddressHeader)){
                    StunMappedAddressHeader addr_hdr;
                    std::memcpy(&addr_hdr, attr.value.data(), sizeof(StunMappedAddressHeader));

                    uint16_t port = ntohs(addr_hdr.port) ^ (STUN_MAGIC_COOKIE >> 16);
                    uint32_t ip_num = addr_hdr.address ^ htonl(STUN_MAGIC_COOKIE);

                    in_addr inaddr{ip_num};
                    char ip_buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &inaddr, ip_buf, INET_ADDRSTRLEN);

                    out_dest_ep.ip = std::string(ip_buf);
                    out_dest_ep.port = port;
                    found_peer = true;
                }
            }
            else if(attr.type == IceAttributeType::DATA){
                out_payload = attr.value;
                found_data = true;
            }
        }
        return found_data && found_peer;
    }
};

} // namespace comyc::ice_server


#endif // COMYC_ICE_SERVER_TURN_HPP