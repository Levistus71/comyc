#pragma once

#include "src/node/node_utils.hpp"
#include "src/network/packets/cell.hpp"

#include <boost/asio.hpp>
#include <variant>

namespace asio = boost::asio;

constexpr size_t ExitBoundCell_MAX_SZ = 2000;

struct RelayCell{
    size_t bytes_received;
    std::variant<session_id_t,circuit_id_t> id;
    std::array<uint8_t, ExitBoundCell_MAX_SZ> payload;
};


struct ExitInfo{
    asio::ip::udp::endpoint endpoint;
    // sh_cr
};


struct ClientInfo{
    session_id_t session_id;
    asio::ip::udp::endpoint endpoint;
    // sh_cr
};


class Relay : std::enable_shared_from_this<Relay>
{
public:
    Relay(asio::io_context& ioc, asio::ip::udp::socket& sock);
    ~Relay();

    void start();
    // auto stop();

    asio::awaitable<void> forward_packet_exit(std::shared_ptr<RelayCell> packet);
    asio::awaitable<void> forward_packet_client(std::shared_ptr<RelayCell> packet);

private:
    asio::io_context& ioc_;
    asio::ip::udp::socket& udp_socket_;
    RCU_UMap<session_id_t, ExitInfo> sid_ei_umap_;
    RCU_UMap<circuit_id_t, ClientInfo> cid_ci_umap_;

};