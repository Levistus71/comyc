#ifndef COMYC_ICE_SERVER_HOLE_PUNCHER_HPP
#define COMYC_ICE_SERVER_HOLE_PUNCHER_HPP

#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <algorithm>
#include <iostream>
#include <cstring>
#include <fcntl.h>
#include "udp_sock.hpp"
#include "../comms/ice_comms.hpp"

namespace comyc::ice_server{
using namespace comyc::network::sockets;
using namespace comyc::network::comms;

enum class CandidateType{
    HOST,
    SERVER_REFLEXIVE,
    RELAYED
};

struct IceCandidate{
    std::string ip;
    uint16_t port{0};
    CandidateType type;
    uint32_t priority{0};

    // calculate ICE candidate priority
    static uint32_t calculate_priority(CandidateType type, uint16_t component_id = 1){
        uint32_t type_preference = 0;
        switch(type){
            case CandidateType::HOST:               type_preference = 126; break;
            case CandidateType::SERVER_REFLEXIVE:   type_preference = 100; break;
            case CandidateType::RELAYED:            type_preference = 0;   break;             
        }
        return (type_preference<<24) | (65535<<8) | (256-component_id);
    }
};

struct CandidatePair{
    IceCandidate local;
    IceCandidate remote;
    uint64_t priority{0};
    bool connected{false};
    uint8_t transaction_id[12];

    void compute_pair_priority(){
        uint64_t g = local.priority;
        uint64_t d = remote.priority;
        uint64_t min_p = std::min(g, d);
        uint64_t max_p = std::max(g, d);
        priority = (1ULL << 32)*min_p + 2*max_p + (g>d ? 1:0);

        for(int i=0; i<12; i++){
            transaction_id[i] = static_cast<uint8_t>(rand()%256);
        }
    }
};

class HolePuncher{
private:
    UdpSocket local_sock_;
    std::vector<CandidatePair> pairs_;
    bool is_connected_{false};
    Endpoint active_p2p_endpoint_{};

public:
    HolePuncher() = default;
    ~HolePuncher() = default;

    // initialise the local UDP socket for hole punching
    bool init(uint16_t local_port = 0) {
        if (!local_sock_.open()) return false;
        if (!local_sock_.bind(local_port)) return false;

        // force socket to non-blocking mode inside HolePuncher init
        int fd = local_sock_.get_fd();
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        return true;
    }

    // add candidate pairs discovered during ICE gathering
    void add_candidate_pair(const IceCandidate& local, const IceCandidate& remote){
        CandidatePair pair{local, remote, 0, false, {}};
        pair.compute_pair_priority();
        pairs_.push_back(pair);

        // sort the list (highest priority pair first)
        std::sort(pairs_.begin(), pairs_.end(), [](const CandidatePair& a, const CandidatePair& b){
            return a.priority > b.priority;
        });
    }

    // execute hole punching connectivity checks
    bool punch_holes(int max_attempts=10, int timeout_ms=50){
        if(pairs_.empty()) return false;

        std::vector<uint8_t> recv_buf(2048);

        for(int attempt=0; attempt<max_attempts; attempt++){
            for(auto& pair : pairs_){
                if(pair.connected) continue;

                // 1. craft STUN binding request probe
                IcePacket probe_pkt;
                probe_pkt.set_type(IceMessageType::BINDING_REQUEST);
                probe_pkt.set_transaction_id(pair.transaction_id);

                std::vector<uint8_t> serialized_probe = probe_pkt.serialize();
                Endpoint dest_ep{pair.remote.ip, pair.remote.port};

                // 2. fire outbound STUN probe datagram
                local_sock_.send_to(serialized_probe, dest_ep);
            }

            // sleep briefly to give network time to reflect packet back
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));

            // 3. listen non-blockingly for incoming STUN response
            Endpoint sender_ep;
            ssize_t bytes_read = 0;
            while ((bytes_read = local_sock_.recv_from(recv_buf.data(), recv_buf.size(), sender_ep)) > 0) {
                IcePacket resp_pkt;
                if (IcePacket::deserialize(recv_buf.data(), static_cast<size_t>(bytes_read), resp_pkt)) {
                    if (resp_pkt.get_type() == IceMessageType::BINDING_RESPONSE) {
                        for (auto& pair : pairs_) {
                            if (std::memcmp(resp_pkt.header.transaction_id, pair.transaction_id, 12) == 0) {
                                pair.connected = true;
                                is_connected_ = true;
                                active_p2p_endpoint_ = sender_ep;

                                std::cout << "[Hole Puncher] Success! Direct P2P link established with "
                                        << sender_ep.ip << ":" << sender_ep.port << std::endl;
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return is_connected_;
    }

    bool is_connected() const {return is_connected_;}
    Endpoint get_active_endpoint() const {return active_p2p_endpoint_;}
    UdpSocket& get_socket() {return local_sock_;}
};

} // namespace comyc::ice_server

#endif // COMYC_ICE_SERVER_HOLE_PUNCHER_HPP