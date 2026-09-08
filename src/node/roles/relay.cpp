#include "src/node/roles/relay.hpp"

#include <iostream>

Relay::Relay(asio::io_context& ioc, asio::ip::udp::socket& sock):
    ioc_(ioc),
    udp_socket_(sock)
{

}

Relay::~Relay(){

}


void Relay::start(){
    // todo: actual start up idk what to do here
}


asio::awaitable<void> Relay::forward_packet_exit(std::shared_ptr<RelayCell> packet){
    std::shared_ptr<ExitInfo> exit_info = nullptr;
    if(std::holds_alternative<session_id_t>(packet->id)){
        exit_info = sid_ei_umap_.get(std::get<session_id_t>(packet->id));
    }
    if(exit_info==nullptr){
        std::cerr << "[Relay] Dropping invalid packet, no session_id map found." << std::endl;
        co_return;
    }

    // todo: decrypt(packet->payload + sizeof(session_id), exit_info->sh_cr);

    size_t outgoing_bytes = packet->bytes_received - sizeof(session_id_t);
    udp_socket_.async_send_to(
        asio::buffer(packet->payload.data()+sizeof(session_id_t), outgoing_bytes),
        exit_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [keep_alive = packet, outgoing_bytes](const boost::system::error_code& ec, size_t bytes_xfer){
            if(ec){
                std::cerr << "[Relay] Exit send failed: " << ec.message() << std::endl;
                return;
            }
            if(bytes_xfer!=outgoing_bytes){
                std::cerr << "[Relay] Bytes sent mismatch: udp socket fail?" << std::endl;
            }
        }
    );
}


asio::awaitable<void> Relay::forward_packet_client(std::shared_ptr<RelayCell> packet){
    std::shared_ptr<ClientInfo> client_info = nullptr;
    if(std::holds_alternative<circuit_id_t>(packet->id)){
        client_info = cid_ci_umap_.get(std::get<circuit_id_t>(packet->id));
    }
    if(client_info == nullptr){
        std::cerr << "[Relay] Dropping invalid packet, no circuit_id found." << std::endl;
        co_return;
    }

    // todo: encrypt(packet->payload + sizeof(circuit_id_t), client_info->sh_cr);

    size_t outgoing_bytes = packet->bytes_received + sizeof(session_id_t);
    std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(&client_info->session_id, sizeof(session_id_t)),
        asio::buffer(packet->payload, packet->bytes_received)
    };

    udp_socket_.async_send_to(
        outgoing,
        client_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [keep_alive = packet, outgoing_bytes](const boost::system::error_code& ec, size_t bytes_xfer){
            if(ec){
                std::cerr << "[Relay] Exit send failed: " << ec.message() << std::endl;
                return;
            }
            if(bytes_xfer!=outgoing_bytes){
                std::cerr << "[Relay] Bytes sent mismatch: udp socket fail?" << std::endl;
            }
        }
    );
}