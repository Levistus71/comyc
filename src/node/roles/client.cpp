#include "src/node/roles/client.hpp"
#include "src/network/sockets/utun.hpp"
#include "src/network/packets/packets.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <unistd.h>

#include <boost/asio.hpp>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>

namespace asio = boost::asio;


Client::Client(asio::io_context& ioc) : ioc_(ioc), utun_stream_(ioc_)
{

}

Client::~Client()
{
    if(utun_sockfd_>=0){
        //* close_utun();
        close(utun_sockfd_);
    }
}


void Client::start()
{

    //* connect_control_server();

    //* utun_sockfd_ = setup_tun();

    // ! START: simulating utun traffic
    int utun_create_fd = -1;
    try{
        std::tie(utun_create_fd, utun_sockfd_) = utun::dummy_tun();
    }
    catch(const std::runtime_error& e){
        return;
    }
    
    std::thread worker(utun::simulate_utun, utun_create_fd);
    if(worker.joinable())
        worker.detach();
    // ! END

    start_utun();
}


void Client::start_utun()
{
    boost::system::error_code ec;
    
    utun_stream_.assign(utun_sockfd_, ec);

    if(ec){
        std::cerr << "[Tun Worker] Failed to convert utun_sockfd_ to asio stream_descriptor" << std::endl;
        return;
    }

    std::shared_ptr<utun::RawPacket> raw_packet = std::make_shared<utun::RawPacket>();
    read_packet(raw_packet);
}


void Client::read_packet(std::shared_ptr<utun::RawPacket> raw_packet)
{
    // TODO: check if this reads whole packet. if it doesn't, how do we make it read the whole packet?
    utun_stream_.async_read_some(
        asio::buffer(raw_packet->payload),
        [me=shared_from_this(), raw_packet](const boost::system::error_code& ec, std::size_t bytes_xfer)
        {
            raw_packet->bytes_received = bytes_xfer;
            me->loop_utun(raw_packet, ec);
        }
    );
}


void Client::loop_utun(std::shared_ptr<utun::RawPacket> raw_packet, boost::system::error_code const& ec)
{
    if(ec){
        std::cerr << "[Tun Worker] Raw packet read failed: " << ec.message() << std::endl;
        return;
    }
    
    std::shared_ptr<utun::RawPacket> new_raw_packet = std::make_shared<utun::RawPacket>();
    read_packet(new_raw_packet);
    
    process_raw_packet(raw_packet);
}


// multithread_care
void Client::process_raw_packet(std::shared_ptr<utun::RawPacket> raw_packet)
{
    if(!raw_packet->parse_packet()){
        std::cerr << "[Tun Worker] Dropping faulty packet." << std::endl;
        return;
    }

    // map: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id}
    // {circuit_id} : {SH_CE, vector<session_id>}
    // {session_id} : {SH_CR, circuit_id, socket_info}
    
    /*

    ? imp traffic maps:
    outbound: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id, SH_CE, vector<session_id,SH_CR,socket_info,relay_performance>}
    inbound: {session_id} : {SH_CR, SH_CE, jitter_buffer addr}

    */

}