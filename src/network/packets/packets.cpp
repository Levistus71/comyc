#include "network/packets/packets.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <random>
#include <unistd.h>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>

namespace utun{

// bool RawPacket::blocking_listen_utun(asio::posix::stream_descriptor& utun_stream,
//     std::function<void(boost::system::error_code)> handler)
// {
//     if(!parse_macos_header(utun_stream))
//         return false;

//     if(!parse_ip_header(utun_stream))
//         return false;
    
//     if(!get_payload(utun_stream))
//         return false;        

//     if(!process_packet())
//         return false;

//     return true;
// }

asio::awaitable<void> RawPacket::async_listen_utun(std::shared_ptr<asio::posix::stream_descriptor> utun_stream,
    std::function<void(boost::system::error_code)> exit_routine)
{
     
}



bool RawPacket::parse_macos_header(asio::posix::stream_descriptor& utun_stream){
    boost::system::error_code ec;
    asio::read(utun_stream, asio::buffer(&family_hdr, sizeof(family_hdr)), ec);
    if(ec){
        std::cerr << "[Tun Worker] Header read failed: " << ec.message() << std::endl;
        return false;
    }

    if(family_hdr == AF_INET)
        ip_hdr_sz = sizeof(struct ip);
    else if(family_hdr == AF_INET6)
        ip_hdr_sz = sizeof(struct ip6_hdr);
    else{
        std::cerr << "[Tun Worker] Unknown family header: " << family_hdr << std::endl;
        return false;
    }

    return {};
}


bool RawPacket::parse_ip_header(asio::posix::stream_descriptor& utun_stream){
    boost::system::error_code ec;
    payload.resize(ip_hdr_sz);

    asio::read(utun_stream, asio::buffer(payload), ec);
    if(ec){
        std::cerr << "[Tun Worker] IP header read failed: " << ec.message() << std::endl;
        return false;
    }

    if(family_hdr == AF_INET){
        auto* iph = reinterpret_cast<const struct ip*>(payload.data());
        total_packet_len = ntohs(iph->ip_len);
    }
    else{
        auto* ip6h = reinterpret_cast<const struct ip6_hdr*>(payload.data());
        total_packet_len = sizeof(struct ip6_hdr) + ntohs(ip6h->ip6_plen);
    }

    return true;
}


bool RawPacket::get_payload(asio::posix::stream_descriptor& utun_stream){
    size_t curr_sz = payload.size();
    boost::system::error_code ec;
    if(total_packet_len>curr_sz){
        size_t remaining_bytes = total_packet_len - curr_sz;
        payload.resize(total_packet_len);

        asio::read(utun_stream, asio::buffer(payload.data() + curr_sz, remaining_bytes), ec);

        if(ec){
            std::cerr << "[Tun Worker] Payload read failed: " << ec.message() << std::endl;
            return false;
        }
    }

    return true;
}


bool RawPacket::process_packet(){
    if(payload.empty())
        return false;
    
    if(ip_hdr_sz > payload.size())
        return false;

    std::array<char, INET6_ADDRSTRLEN> src_str{};
    std::array<char, INET6_ADDRSTRLEN> dst_str{};
    uint8_t protocol = 0;

    if(family_hdr == AF_INET){
        if(payload.size() < sizeof(struct ip))
            return false;
        
        auto* iph = reinterpret_cast<const struct ip*>(payload.data());
        inet_ntop(AF_INET, &iph->ip_src, src_str.data(), src_str.size());
        inet_ntop(AF_INET, &iph->ip_dst, dst_str.data(), dst_str.size());
        protocol = iph->ip_p;
    } 
    else if(family_hdr == AF_INET6){
        if(payload.size() < sizeof(struct ip6_hdr))
            return false;
        
        auto* ip6h = reinterpret_cast<const struct ip6_hdr*>(payload.data());
        inet_ntop(AF_INET6, &ip6h->ip6_src, src_str.data(), src_str.size());
        inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_str.data(), dst_str.size());
        protocol = ip6h->ip6_nxt;
    }
    else
        return false;

    if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP){
        if(payload.size() - ip_hdr_sz < 4)
            return false;

        const auto* p = payload.data() + ip_hdr_sz;

        uint16_t src, dst;
        std::memcpy(&src, p, sizeof(src));
        std::memcpy(&dst, p + 2, sizeof(dst));

        src_port  = ntohs(src);
        dest_port = ntohs(dst);
    }

    try{
        src_addr = boost::asio::ip::make_address(src_str.data());
        dest_addr = boost::asio::ip::make_address(dst_str.data());
    }
    catch (const boost::system::system_error& e) {
        std::cerr << "[Tun Worker] Failed to get ip information properly: " << e.what() << std::endl;
        return false;
    }

    return true;
}


}