#include "node/roles/client.hpp"
#include "network/sockets/utun.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>


void Client::start_(){

}


void Client::start(){
    running_ = true;

    //* connect_control_server();

    //* utun_sockfd_ = setup_tun();

    // ! START: simulating utun traffic
    int utun_create_fd = -1;
    try{
        std::tie(utun_create_fd, utun_sockfd_) = UTUN::dummy_tun();
    }
    catch(const std::runtime_error& e){
        return;
    }
    
    std::thread worker(UTUN::simulate_utun, utun_create_fd);
    if(worker.joinable())
        worker.detach();
    // ! END

    tun_worker_ = std::thread(&Client::start_, this);
}


Client::~Client(){
    running_ = false;
    if(utun_sockfd_>=0)
        close(utun_sockfd_);
    
    if(tun_worker_.joinable()){
        tun_worker_.join();
    }
}