#pragma once

#include "src/node/node_utils.hpp"
#include "src/network/packets/cell.hpp"

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
    Relay(asio::io_context& ioc, asio::ip::udp::socket& sockv4, asio::ip::udp::socket& sockv6);


    ~Relay();


    void start();


    void stop();


    asio::awaitable<void> forward_to_exit(std::shared_ptr<IncomingCell> packet);


    asio::awaitable<void> forward_to_client(std::shared_ptr<IncomingCell> packet);

private:
    asio::io_context& ioc_;
    asio::ip::udp::socket& udp_socketv4_;
    asio::ip::udp::socket& udp_socketv6_;
    RCU_UMap<session_id_t, ExitInfo> sid_ei_umap_;
    RCU_UMap<circuit_id_t, ClientInfo> cid_ci_umap_;
    quill::Logger* logger_{nullptr};
};
