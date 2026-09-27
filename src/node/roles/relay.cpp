#include "src/node/roles/relay.hpp"

#include <quill/LogMacros.h>
#include <quill/Frontend.h>


Relay::Relay(asio::io_context& ioc, asio::ip::udp::socket& sockv4, asio::ip::udp::socket& sockv6):
    ioc_(ioc),
    udp_socketv4_(sockv4),
    udp_socketv6_(sockv6){
    logger_ = quill::Frontend::get_logger("relay_logger");
}


Relay::~Relay() = default;


void Relay::start(){
    // todo: actual start up idk what to do here
}


void Relay::stop(){
    // todo: signal clients about exit
}


/*
incoming packet:
    route_flag
    session_id
    {thdr, phdr, payload}
outgoing packet:
    route_flag
    {thdr, phdr, payload}
*/
[[nodiscard]] static bool parse_packet_from_client(std::shared_ptr<IncomingCell> packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(session_id_t)){
        return false;
    }

    packet->sid = (static_cast<session_id_t>(packet->payload[1]) << 24) |
                  (static_cast<session_id_t>(packet->payload[2]) << 16) |
                  (static_cast<session_id_t>(packet->payload[3]) << 8) |
                  static_cast<session_id_t>(packet->payload[4]);

    packet->outgoing_bytes = packet->bytes_received - sizeof(session_id_t);
    packet->payload_bytes = packet->bytes_received - sizeof(RoutingFlag) - sizeof(session_id_t);
    packet->start_offset = sizeof(RoutingFlag) + sizeof(session_id_t);
    packet->route_flag = RoutingFlag::RELAY_TO_EXIT;

    return true;
}


asio::awaitable<void> Relay::forward_to_exit(std::shared_ptr<IncomingCell> packet){
    if(!parse_packet_from_client(packet)){
        LOG_ERROR(logger_, "Dropping faulty packet, route_packet, size<5.");
        co_return;
    }

    std::shared_ptr<ExitInfo> exit_info = sid_ei_umap_.get(packet->sid);
    if(exit_info == nullptr){
        LOG_ERROR(logger_, "Dropping invalid packet, no session_id map found.");
        co_return;
    }

    // todo: decrypt(packet->payload + sizeof(session_id), exit_info->sh_cr);

    /*
    incoming packet:
        route_flag
        session_id
        {thdr, phdr, payload}
    outgoing packet:
        route_flag
        {thdr, phdr, payload}
    */
    std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(&packet->route_flag, sizeof(RoutingFlag)),
        asio::buffer(packet->payload.data() + packet->start_offset, packet->payload_bytes)
    };

    asio::ip::udp::socket& sock = (exit_info->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

    sock.async_send_to(
        outgoing,
        exit_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), keep_alive = packet](const boost::system::error_code& ec, size_t bytes_xfer){
            if(ec){
                LOG_ERROR(me->logger_, "[Relay] Exit send failed: {}", ec.message());
                return;
            }
            if(bytes_xfer != keep_alive->outgoing_bytes){
                LOG_ERROR(me->logger_, "[Relay] Bytes sent mismatch: udp socket fail?");
            }
        }
    );
}


/*
incoming packet:
    route_flag
    {thdr, phdr, payload}
outgoing packet:
    route_flag
    session_id
    {thdr, phdr, payload}
*/
[[nodiscard]] static bool parse_packet_from_exit(std::shared_ptr<IncomingCell> packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(circuit_id_t)){
        return false;
    }

    packet->cid = 0;
    size_t loops = sizeof(circuit_id_t) / sizeof(uint8_t);
    for(size_t i = 0; i < loops; i++){
        uint8_t byte = static_cast<circuit_id_t>(packet->payload[i + sizeof(RoutingFlag)]);
        size_t shift = 8 * (loops - i - 1);
        packet->cid |= (byte << shift);
    }

    packet->outgoing_bytes = packet->bytes_received + sizeof(session_id_t);
    packet->payload_bytes = packet->bytes_received - sizeof(RoutingFlag);
    packet->start_offset = sizeof(RoutingFlag);
    packet->route_flag = RoutingFlag::RELAY_TO_CLIENT;

    return true;
}


asio::awaitable<void> Relay::forward_to_client(std::shared_ptr<IncomingCell> packet){
    if(!parse_packet_from_exit(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, size<5.");
        co_return;
    }

    std::shared_ptr<ClientInfo> client_info = cid_ci_umap_.get(packet->cid);
    if(client_info == nullptr){
        LOG_WARNING(logger_, "Dropping invalid packet, no circuit_id found.");
        co_return;
    }
    packet->sid = client_info->session_id;

    // todo: encrypt(packet->payload + sizeof(circuit_id_t), client_info->sh_cr);

    /*
    incoming packet:
        route_flag
        {thdr, phdr, payload}
    outgoing packet:
        route_flag
        session_id
        {thdr, phdr, payload}
    */
    std::array<asio::const_buffer, 3> outgoing = {
        asio::buffer(&packet->route_flag, sizeof(RoutingFlag)),
        asio::buffer(&packet->sid, sizeof(session_id_t)),
        asio::buffer(packet->payload.data() + packet->start_offset, packet->payload_bytes)
    };

    asio::ip::udp::socket& sock = (client_info->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

    sock.async_send_to(
        outgoing,
        client_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), keep_alive = packet]
    (const boost::system::error_code& ec, size_t bytes_xfer){
            if(ec){
                LOG_ERROR(me->logger_, "Exit send failed: {}", ec.message());
                return;
            }
            if(keep_alive->outgoing_bytes != bytes_xfer){
                LOG_ERROR(me->logger_, "Bytes sent mismatch: udp socket fail?");
            }
        }
    );
}
