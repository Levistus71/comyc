#include "src/node/node.hpp"

#include "quill/LogMacros.h"
#include "quill/Frontend.h"


Node::Node(asio::io_context& ioc, const NodeRole role):
    role_(role),
    ioc_(ioc),
    udp_socketv4_(ioc_),
    udp_socketv6_(ioc_),
    listening_endpoint_(asio::ip::udp::endpoint(asio::ip::udp::v4(), 12345)),
    incoming_cell_pool_(16834, "node_logger"){
    logger_ = quill::Frontend::get_logger("node_logger");

    // todo: start client, start relay, start exit? based on the role.
    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::CLIENT))
        client_ = std::make_shared<Client>(ioc_, udp_socketv4_, udp_socketv6_);

    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::RELAY))
        relay_ = std::make_shared<Relay>(ioc_, udp_socketv4_, udp_socketv6_);

    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::EXIT))
        exit_ = std::make_shared<Exit>();

    ignore_endpoint_ = std::make_shared<asio::ip::udp::endpoint>(asio::ip::udp::v4(), 8008);
}


[[nodiscard]] bool Node::start(){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "start() called when running_.");
        return false;
    }

    boost::system::error_code ec;
    udp_socketv4_.open(asio::ip::udp::v4(), ec);
    if(ec){
        LOG_ERROR(logger_, "udp_socketv4_ failed to open.");
        return false;
    }

    ec.clear();
    udp_socketv6_.open(asio::ip::udp::v6(), ec);
    if(ec){
        LOG_ERROR(logger_, "udp_socketv6_ failed to open.");
        return false;
    }


    if(client_ != nullptr){
        if(!client_->start()){
            LOG_ERROR(logger_, "Client not started.");
            return false;
        }
    }

    if(relay_ != nullptr)
        relay_->start();

    if(exit_ != nullptr)
        exit_->start();

    auto first_packetv4 = incoming_cell_pool_.alloc();
    listenv4(std::move(first_packetv4));
    auto first_packetv6 = incoming_cell_pool_.alloc();
    listenv6(std::move(first_packetv6));

    return true;
}


void Node::stop(){
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "stop() called when not running_.");
        return;
    }

    if(client_ != nullptr)
        client_->stop();

    if(relay_ != nullptr)
        relay_->stop();

    if(exit_ != nullptr)
        exit_->stop();

    boost::system::error_code ec;
    udp_socketv4_.close(ec);
    if(ec){
        LOG_ERROR(logger_, "Error closing udp socket v4: {}", ec.message());
    }

    ec.clear();
    udp_socketv6_.close(ec);
    if(ec){
        LOG_ERROR(logger_, "Error closing udp socket v6: {}", ec.message());
    }
}


void Node::listenv4(ArenaSlot<IncomingCell> packet){
    udp_socketv4_.async_receive_from(
        asio::buffer(packet->payload),
        (*ignore_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable {
            pkt->bytes_received = bytes_received;
            me->loop_listen(std::move(pkt), ec, true);
        }
    );
}


void Node::listenv6(ArenaSlot<IncomingCell> packet){
    udp_socketv6_.async_receive_from(
        asio::buffer(packet->payload),
        (*ignore_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
            pkt->bytes_received = bytes_received;
            me->loop_listen(std::move(pkt), ec, false);
        }
    );
}


void Node::loop_listen(ArenaSlot<IncomingCell> packet, const boost::system::error_code& ec, bool ipv4){
    if(ec){
        LOG_ERROR(logger_, "Packet receive failed in loop_listen(): {}", ec.message());
        return;
    }

    ArenaSlot<IncomingCell> new_packet = incoming_cell_pool_.alloc();
    if(ipv4)
        listenv4(std::move(new_packet));
    else
        listenv6(std::move(new_packet));

    route_packet(std::move(packet));
}


void Node::route_packet(ArenaSlot<IncomingCell> packet) const{
    if(packet->bytes_received < sizeof(RoutingFlag)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, size<1.");
        return;
    }
    packet->route_flag = static_cast<RoutingFlag>(packet->payload[0]);

    switch(packet->route_flag){
        case RoutingFlag::CLIENT_TO_RELAY: {
            asio::post(
                ioc_,
                [me = shared_from_this(), pkt = std::move(packet)]() mutable{
                    me->relay_->forward_to_exit(std::move(pkt));
                }
            );
            return;
        }
        case RoutingFlag::EXIT_TO_RELAY: {
            asio::post(
                ioc_,
                [me = shared_from_this(), pkt = std::move(packet)]() mutable{
                    me->relay_->forward_to_client(std::move(pkt));
                }
            );
            return;
        }
        case RoutingFlag::RELAY_TO_CLIENT: {
            asio::post(
                ioc_,
                [me = shared_from_this(), pkt = std::move(packet)]() mutable{
                    me->client_->process_incoming_packet(std::move(pkt));
                }
            );
            return;
        }
        case RoutingFlag::RELAY_TO_EXIT: {
            asio::post(
                ioc_,
                [me = shared_from_this(), pkt = std::move(packet)]() mutable{
                    me->exit_->process_incoming_packet(std::move(pkt));
                }
            );
            return;
        }
        default: {
            LOG_WARNING(logger_, "Dropping faulty packet, invalid routing flag.");
            return;
        }
    }
}
