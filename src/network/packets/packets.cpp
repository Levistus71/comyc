#include "src/network/packets/packets.hpp"

#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>


namespace utun{
[[nodiscard]] bool RawPacket::parse_packet(){
#if defined(__APPLE__)
    if(!parse_macos_header())
        return false;
    return parse_headers(sizeof(family_hdr));
#elif defined(__linux__)
    family_hdr = 0;
    return parse_headers(0);
#else
    return false;
#endif
}


[[nodiscard]] bool RawPacket::parse_macos_header(){
    if(bytes_received < sizeof(family_hdr))
        return false;

    std::memcpy(&family_hdr, payload.data(), sizeof(family_hdr));
    family_hdr = ntohl(family_hdr);

    if(family_hdr == AF_INET)
        ip_hdr_sz = sizeof(struct ip);
    else if(family_hdr == AF_INET6)
        ip_hdr_sz = sizeof(struct ip6_hdr);
    else{
        // std::cerr << "[Tun Worker] Unknown family header: " << family_hdr << std::endl;
        return false;
    }

    return true;
}


[[nodiscard]] bool RawPacket::parse_headers(const size_t header_offset){
#if defined(__linux__)
    if(bytes_received < header_offset + 1){
        return false;
    }
    const uint8_t ip_version = payload[header_offset] >> 4;
    if(ip_version == 4){
        family_hdr = AF_INET;
        ip_hdr_sz = sizeof(struct ip);
    }
    else if(ip_version == 6){
        family_hdr = AF_INET6;
        ip_hdr_sz = sizeof(struct ip6_hdr);
    }
    else{
        return false;
    }
#endif

    if(bytes_received < header_offset + ip_hdr_sz){
        return false;
    }

    const uint8_t* headers_start = payload.data() + header_offset;
    uint8_t protocol = 0;

    if(family_hdr == AF_INET){
        const auto* iph = reinterpret_cast<const struct ip*>(headers_start);

        ip_hdr_sz = iph->ip_hl * 4;
        if(ip_hdr_sz < 20 || bytes_received < header_offset + ip_hdr_sz){
            return false;
        }

        total_packet_len = ntohs(iph->ip_len);

        asio::ip::address_v4::bytes_type src_bytes, dst_bytes;
        std::memcpy(src_bytes.data(), &iph->ip_src, 4);
        std::memcpy(dst_bytes.data(), &iph->ip_dst, 4);

        src_addr = asio::ip::address_v4(src_bytes);
        dest_addr = asio::ip::address_v4(dst_bytes);

        protocol = iph->ip_p;
    }
    else if(family_hdr == AF_INET6){
        const auto* ip6h = reinterpret_cast<const struct ip6_hdr*>(headers_start);

        ip_hdr_sz = sizeof(struct ip6_hdr);
        total_packet_len = sizeof(struct ip6_hdr) + ntohs(ip6h->ip6_plen);

        asio::ip::address_v6::bytes_type src_bytes, dst_bytes;
        std::memcpy(src_bytes.data(), &ip6h->ip6_src, 16);
        std::memcpy(dst_bytes.data(), &ip6h->ip6_dst, 16);

        src_addr = asio::ip::address_v6(src_bytes);
        dest_addr = asio::ip::address_v6(dst_bytes);

        protocol = ip6h->ip6_nxt;
    }
    else{
        return false;
    }

    if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP){
        if(bytes_received < header_offset + ip_hdr_sz + 4){
            return false;
        }

        const uint8_t* transport_start = payload.data() + header_offset + ip_hdr_sz;

        uint16_t src = 0;
        uint16_t dst = 0;
        std::memcpy(&src, transport_start, sizeof(src));
        std::memcpy(&dst, transport_start + 2, sizeof(dst));

        src_port = ntohs(src);
        dest_port = ntohs(dst);
    }

    return true;
}
}
