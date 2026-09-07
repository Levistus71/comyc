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


Client::Client(asio::io_context& ioc, asio::ip::udp::socket& udp_socket) : 
    ioc_(ioc), 
    utun_stream_(ioc_), 
    udp_socket_(udp_socket)
{
    ci_computing_strand_ = asio::make_strand(ioc_);
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
asio::awaitable<void> Client::process_raw_packet(std::shared_ptr<utun::RawPacket> raw_packet)
{
    if(!raw_packet->parse_packet()){
        std::cerr << "[Tun Worker] Dropping faulty packet." << std::endl;
        return;
    }

    // map: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id}
    // {circuit_id} : {SH_CE, vector<session_id>}
    // {session_id} : {SH_CR, circuit_id, socket_info}
    
    /*

    outbound: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id, SH_CE, vector<session_id,SH_CR,socket_info,relay_performance>}
    inbound: {session_id} : {SH_CR, SH_CE, jitter_buffer addr}

    */
    
    NetworkTuple nt{
        .src_addr = raw_packet->src_addr,
        .dest_addr = raw_packet->dest_addr,

        .src_port = raw_packet->src_port,
        .dest_port = raw_packet->dest_port,
    };

    auto ci = nt_ci_umap_.get(nt);
    if(ci==nullptr){
        ci = co_await make_new_circuit(nt);
    }
    
    // further processing

}


// multithread_care
asio::awaitable<std::shared_ptr<CircuitInfo>> Client::make_new_circuit(const NetworkTuple& nt){
    co_return co_await asio::co_spawn(
        ci_computing_strand_, 
        make_new_circuit_helper(nt), 
        asio::use_awaitable
    );
}

// stranded
asio::awaitable<std::shared_ptr<CircuitInfo>> Client::make_new_circuit_helper(const NetworkTuple& nt){

    // NOT PIONEER PACKETS
    if(auto it = ci_computing_.find(nt); it!=ci_computing_.end()){
        auto chan = it->second;
        co_return co_await chan->async_receive(asio::use_awaitable);
    }
    // if already completed when we were competing for the strand
    {
        auto t = nt_ci_umap_.get(nt);
        if(t!=nullptr){
            co_return t;
        }
    }

    // PIONEER PACKET
    ci_computing_[nt] = std::make_shared<CircuitChannel>(ci_computing_strand_.get_inner_executor(), 100);
    
    // TODO: co_await async_compute_ci(nt);
    CircuitInfo ci = CircuitInfo{
        .circuit_id = 1232938,
        .sequence_id_ptr = std::make_shared<std::atomic<int>>(23412),
        .relays = std::vector<RelayInfo>{
            RelayInfo{
                .session_id = 12321344,
                .endpoint = asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 6000),
            }
        }
    };
    nt_ci_umap_.put(nt,std::move(ci));
    auto val = nt_ci_umap_.get(nt);

    auto active_chan = std::move(ci_computing_[nt]);
    ci_computing_.erase(nt);
    while(active_chan->ready()){
        active_chan->try_send(boost::system::error_code{}, val);
    }
    active_chan->close();

    co_return val;
}
