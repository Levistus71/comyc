#pragma once

#include "src/node/node_utils.hpp"
#include "src/network/packets/cell.hpp"
#include "src/node/buffers/arena_allocator.hpp"

#include <boost/asio.hpp>

#include <quill/Logger.h>


namespace asio = boost::asio;


struct ExitInfo{
    asio::ip::udp::endpoint endpoint;
    // sh_cr
};


struct ClientInfo{
    session_id_t session_id;
    asio::ip::udp::endpoint endpoint;
    // sh_cr
};


class Relay : public std::enable_shared_from_this<Relay>{
public:
    Relay(asio::io_context& ioc,
          std::shared_ptr<asio::ip::udp::socket> sockv4,
          std::shared_ptr<asio::ip::udp::socket> sockv6,
          std::shared_ptr<RelaysInfoGlb>);


    ~Relay();


    void start();


    void stop();


    void process_packet_from_client(ArenaSlot<IncomingCell> packet, const asio::ip::udp::endpoint& sender_endpoint);


    void process_packet_from_exit(ArenaSlot<IncomingCell> packet);

private:
    asio::io_context& ioc_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv4_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv6_;
    std::shared_ptr<RelaysInfoGlb> known_relays_;
    RCU_UMap<session_id_t, ExitInfo> sid_ei_umap_;
    RCU_UMap<circuit_id_t, ClientInfo> cid_ci_umap_;
    RCU_UMap<session_id_t, ClientInfo> sid_ci_umap_;
    quill::Logger* logger_{nullptr};


    void handle_control_from_client(session_id_t sid, const uint8_t* data, size_t len, const asio::ip::udp::endpoint& sender_endpoint);


    void forward_to_exit(ArenaSlot<IncomingCell> packet);


    void forward_to_client(ArenaSlot<IncomingCell> packet);
};
