#include "src/node/node.hpp"

#include <iostream>

#include "quill/LogMacros.h"
#include "quill/Frontend.h"


Node::Node(asio::io_context& ioc, const NodeRole role):
    role_(role),
    ioc_(ioc),
    udp_socket_(ioc_),
    listening_endpoint_(asio::ip::udp::endpoint(asio::ip::udp::v4(), 12345)){
    logger_ = quill::Frontend::get_logger("node_logger");

    // todo: start client, start relay, start exit? based on the role.
    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::CLIENT))
        client_ = std::make_shared<Client>(ioc_, udp_socket_);

    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::RELAY))
        relay_ = std::make_shared<Relay>(ioc_, udp_socket_);

    if(static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::EXIT))
        exit_ = std::make_shared<Exit>();

    ignore_endpoint_ = std::make_shared<asio::ip::udp::endpoint>(asio::ip::udp::v4(), 8008);
}


void Node::start(){
    if(bool expected = false; running_.compare_exchange_strong(expected, true)==false){
        LOG_ERROR(logger_, "start() called when running_.");
        return;
    }

    if(client_ != nullptr){
        if(!client_->start()){
            LOG_ERROR(logger_, "Client not started.");
        }
    }

    if(relay_ != nullptr)
        relay_->start();

    if(exit_ != nullptr)
        exit_->start();

    const auto first_packet = std::make_shared<IncomingCell>();
    listen(first_packet);
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
    udp_socket_.close(ec);

    if(ec){
        LOG_ERROR(logger_, "Error closing udp socket: {}", ec.message());
    }
}


void Node::listen(const std::shared_ptr<IncomingCell>& packet){
    udp_socket_.async_receive_from(
        asio::buffer(packet->payload),
        (*ignore_endpoint_),
        [me=shared_from_this(), packet](const boost::system::error_code& ec, const size_t bytes_received){
            packet->bytes_received = bytes_received;
            me->loop_listen(packet, ec);
        }
    );
}


void Node::loop_listen(const std::shared_ptr<IncomingCell>& packet, const boost::system::error_code& ec){
    if(ec){
        LOG_ERROR(logger_, "Packet receive failed in loop_listen(): {}", ec.message());
        return;
    }

    std::shared_ptr<IncomingCell> new_packet = std::make_shared<IncomingCell>();
    listen(new_packet);

    route_packet(packet);
}


void Node::route_packet(const std::shared_ptr<IncomingCell>& packet){
    if(packet->bytes_received < sizeof(RoutingFlag)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, size<1.");
        return;
    }
    packet->route_flag = static_cast<RoutingFlag>(packet->payload[0]);

    switch(packet->route_flag){
        case RoutingFlag::CLIENT_TO_RELAY: {
            asio::co_spawn(
                ioc_,
                relay_->forward_to_exit(packet),
                asio::detached
            );
            return;
        }
        case RoutingFlag::EXIT_TO_RELAY: {
            asio::co_spawn(
                ioc_,
                relay_->forward_to_client(packet),
                asio::detached
            );
            return;
        }
        case RoutingFlag::RELAY_TO_CLIENT: {
            client_->process_incoming_packet(packet);
            return;
        }
        case RoutingFlag::RELAY_TO_EXIT: {
            exit_->process_incoming_packet(packet);
            return;
        }
        default: {
            LOG_WARNING(logger_, "Dropping faulty packet, invalid routing flag.");
            return;
        }
    }
}
