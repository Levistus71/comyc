#include "node/roles/client.hpp"
#include "network/sockets/utun.hpp"
#include "network/packets/packets.hpp"

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


class AsioHandler{
public:
    asio::io_context ioc;
    boost::system::error_code ec;

    AsioHandler() : work_guard_(boost::asio::make_work_guard(ioc)){}
    ~AsioHandler(){
        work_guard_.reset();
        if(ioc_bg_thread_.joinable())
            ioc_bg_thread_.join();
    }
    
    void start(){
        ioc_bg_thread_ = std::thread([this](){
            ioc.run();
        });
    }

private:
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::thread ioc_bg_thread_;
};


void Client::listen_utun(){

    AsioHandler ioch;
    ioch.start();

    utun_stream_ = std::make_shared<asio::posix::stream_descriptor>(ioch.ioc);
    utun_stream_->assign(utun_sockfd_, ioch.ec);

    if(ioch.ec){
        std::cerr << "[Tun Worker] Failed to convert utun_sockfd_ to asio stream_descriptor" << std::endl;
        return;
    }

    loop_utun();    
}


void Client::loop_utun(){
    if(!running_)
        return;
    
    utun::RawPacket raw_packet;

    raw_packet.async_listen_utun(utun_stream_, [this](boost::system::error_code ec){
        if(ec){
            std::cerr << "[Tun Worker] Raw packet read failed: " << ec.message() << std::endl;
            return;
        }

        if(!running_)
            return;
        
        // process packet
        
        loop_utun();
    });
}


void Client::start(){
    running_ = true;

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

    utun_worker_ = std::thread(&Client::listen_utun, this);
}


Client::~Client(){
    running_ = false;
    if(utun_sockfd_>=0){
        //* close_utun();
        close(utun_sockfd_);
    }
    
    if(utun_worker_.joinable()){
        utun_worker_.join();
    }
}