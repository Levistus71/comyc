#include "src/node/node.hpp"

#include <iostream>

Node::Node() : 
    udp_socket_(ioc_),
    listening_endpoint_(asio::ip::udp::endpoint(asio::ip::udp::v4(), 12345))
{

}


void Node::start(){

    auto first_packet = std::make_shared<IncomingCell>();
    listen(first_packet);
}


void Node::listen(std::shared_ptr<IncomingCell> packet){
    auto ignore = std::make_shared<asio::ip::udp::endpoint>();
    udp_socket_.async_receive_from(
        asio::buffer(packet->payload),
        (*ignore),
        [me=shared_from_this(), packet, keep_alive = ignore](const boost::system::error_code& ec, const size_t bytes_received){
            packet->bytes_received = bytes_received;
            me->loop_listen(packet, ec);
        }
    );
}


void Node::loop_listen(std::shared_ptr<IncomingCell> packet, const boost::system::error_code& ec){
    if(ec){
        std::cerr << "[Node] Packet receive failed in loop_listen(): " << ec.message() << std::endl;
        return;
    }

    std::shared_ptr<IncomingCell> new_packet = std::make_shared<IncomingCell>();
    listen(new_packet);

    route_packet(packet);
}


void Node::route_packet(std::shared_ptr<IncomingCell> packet){
    if(packet->bytes_received<sizeof(RoutingFlag)){
        std::cerr << "[Node] Dropping faulty packet, route_packet, size<1." << std::endl;
        return;
    }
    packet->route_flag = static_cast<RoutingFlag>(packet->payload[0]);
    
    switch(packet->route_flag){
        case RoutingFlag::CLIENT_TO_RELAY:{
            asio::co_spawn(
                ioc_,
                relay_->forward_to_exit(packet),
                asio::detached
            );
            return;
        }
        case RoutingFlag::EXIT_TO_RELAY:{
            asio::co_spawn(
                ioc_,
                relay_->forward_to_client(packet),
                asio::detached
            );
            return;
        }
        case RoutingFlag::RELAY_TO_CLIENT:{
            client_->process_incoming_packet(packet);
            return;
        }
        case RoutingFlag::RELAY_TO_EXIT:{
            exit_->process_incoming_packet(packet);
            return;
        }
        default:{
            std::cerr << "[Node] Dropping faulty packet, invalid routing flag." << std::endl;
            return;
        }
    }
}