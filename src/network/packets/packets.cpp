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

bool RawPacket::parse_packet()
{
    return parse_macos_header() && parse_headers();
}



bool RawPacket::parse_macos_header()
{
    if(bytes_received<sizeof(family_hdr))
        return false;

    std::memcpy(&family_hdr, payload.data(), sizeof(family_hdr));
    family_hdr = ntohl(family_hdr);

    if(family_hdr == AF_INET)
        ip_hdr_sz = sizeof(struct ip);
    else if(family_hdr == AF_INET6)
        ip_hdr_sz = sizeof(struct ip6_hdr);
    else{
        std::cerr << "[Tun Worker] Unknown family header: " << family_hdr << std::endl;
        return false;
    }

    return true;
}


bool RawPacket::parse_headers(){
    if(bytes_received<sizeof(family_hdr)+ip_hdr_sz)
        return false;

    auto headers_start = payload.data() + sizeof(family_hdr);

    uint8_t protocol = 0;
    std::array<char, INET6_ADDRSTRLEN> src_str{};
    std::array<char, INET6_ADDRSTRLEN> dst_str{};

    if(family_hdr == AF_INET){
        auto* iph = reinterpret_cast<const struct ip*>(headers_start);
        // while_debug
        total_packet_len = ntohs(iph->ip_len);  // doubt: might break on macos. don't use nthos for macos.

        ip_hdr_sz = iph->ip_hl * 4; // variable header size
        if(ip_hdr_sz < 20 || bytes_received < sizeof(family_hdr) + ip_hdr_sz)
            return false;

        // ::inet_ntop(AF_INET, &iph->ip_src, src_str.data(), src_str.size());
        // ::inet_ntop(AF_INET, &iph->ip_dst, dst_str.data(), dst_str.size());

        asio::ip::address_v4::bytes_type src_bytes, dst_bytes;
        std::memcpy(src_bytes.data(), &iph->ip_src, 4);
        std::memcpy(dst_bytes.data(), &iph->ip_dst, 4);

        src_addr = asio::ip::address_v4(src_bytes);
        dest_addr = asio::ip::address_v4(dst_bytes);

        protocol = iph->ip_p;
    }
    else{
        auto* ip6h = reinterpret_cast<const struct ip6_hdr*>(headers_start);
        total_packet_len = sizeof(struct ip6_hdr) + ntohs(ip6h->ip6_plen);

        // ::inet_ntop(AF_INET6, &ip6h->ip6_src, src_str.data(), src_str.size());
        // ::inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_str.data(), dst_str.size());

        asio::ip::address_v6::bytes_type src_bytes, dst_bytes;
        std::memcpy(src_bytes.data(), &ip6h->ip6_src, 16);
        std::memcpy(dst_bytes.data(), &ip6h->ip6_dst, 16);

        src_addr = asio::ip::address_v6(src_bytes);
        dest_addr = asio::ip::address_v6(dst_bytes);
        
        // imp: we don't care about header extensions in ipv6, we drop all those packets
        // imp: in the protocol == IPPROTO_TCP || UDP check below.
        protocol = ip6h->ip6_nxt;   // doubt: header extensions
    }

    if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP){
        if(bytes_received - ip_hdr_sz - sizeof(family_hdr) < 4)
            return false;

        const auto* p = payload.data() + ip_hdr_sz + sizeof(family_hdr);

        uint16_t src, dst;
        std::memcpy(&src, p, sizeof(src));
        std::memcpy(&dst, p + 2, sizeof(dst));

        src_port  = ntohs(src);
        dest_port = ntohs(dst);
    }

    return true;
}

}