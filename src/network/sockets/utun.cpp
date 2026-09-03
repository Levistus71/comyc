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

namespace utun{

// ! START: remove all these functions, temporarily used by dummy_utun() and simulate_utun()

static std::string random_payload(std::mt19937& rng, size_t min_len = 1300, size_t max_len = 1700) {
    static std::string_view chars = 
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    
    std::uniform_int_distribution<size_t> len_dist(min_len, max_len);
    std::uniform_int_distribution<size_t> char_dist(0, chars.size() - 1);

    size_t length = len_dist(rng);
    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += chars[char_dist(rng)];
    }
    return result;
}

static void simulate_utun(int write_fd){
    std::cout << "[Simulated System] Started writing TUN frames." << std::endl;
    
    std::mt19937 rng(std::random_device{}());
    std::bernoulli_distribution coin_flip(0.5);

    while(true){
        bool ipv4 = coin_flip(rng);
        bool tcp = coin_flip(rng);

        std::string payload = random_payload(rng);
        auto pkt = utun::build_packet(payload, ipv4, tcp);
        
        std::vector<uint8_t> raw_bytes;
        raw_bytes.reserve(sizeof(pkt.os_header) + pkt.raw_packet.size());
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&pkt.os_header);
        raw_bytes.insert(raw_bytes.end(), hdr_ptr, hdr_ptr + sizeof(pkt.os_header));
        
        raw_bytes.insert(raw_bytes.end(), pkt.raw_packet.begin(), pkt.raw_packet.end());

        ssize_t bytes_sent = send(write_fd, raw_bytes.data(), raw_bytes.size(), 0);
        if (bytes_sent < 0) {
            std::perror("[Simulated System] Send failed");
            break;
        }

        std::cout << "[Simulated System] Sent " << bytes_sent << " bytes | "
                  << (ipv4 ? "IPv4" : "IPv6") << " " 
                  << (tcp ? "TCP" : "UDP") << " | " << std::endl;

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}


std::pair<int,int> dummy_tun(){
    int sv[2] = {-1, -1};
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv)<0){
        perror("Socketpair creation failed");
        throw std::runtime_error("Socketpair creation failed.");
    }

    return {sv[0], sv[1]};
}


static UtunPacket build_packet(std::string_view data, bool ipv4, bool tcp){
    size_t tot_sz;
    size_t transport_hdr_size = (tcp) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    std::vector<uint8_t> packet;
    uint8_t* transport_hdr_start;
    uint8_t* data_start;

    // packet ip header
    if(ipv4){
        tot_sz = data.size() + sizeof(struct ip) + transport_hdr_size;
        packet = std::vector<uint8_t>(tot_sz, 0);
        transport_hdr_start = packet.data() + sizeof(struct ip);

        auto* iph = reinterpret_cast<struct ip*>(packet.data());
        iph->ip_v = 4;
        iph->ip_hl = 5;
        iph->ip_tos = 0;
        iph->ip_len = htons(static_cast<uint16_t>(tot_sz));
        iph->ip_id = htons(12345);
        iph->ip_off = 0;
        iph->ip_ttl = 64;
        iph->ip_p = (tcp) ? IPPROTO_TCP : IPPROTO_UDP;
        iph->ip_sum = 0;
        inet_pton(AF_INET, "10.0.0.2", &iph->ip_src);
        inet_pton(AF_INET, "1.1.1.1", &iph->ip_dst);
    }
    else{
        tot_sz = data.size() + sizeof(struct ip6_hdr) + transport_hdr_size;
        packet = std::vector<uint8_t>(tot_sz, 0);
        transport_hdr_start = packet.data() + sizeof(struct ip6_hdr);

        auto* ip6h = reinterpret_cast<struct ip6_hdr*>(packet.data());
        ip6h->ip6_vfc = 0x60;
        ip6h->ip6_plen = htons(static_cast<uint16_t>(transport_hdr_size + data.size()));
        ip6h->ip6_nxt = (tcp) ? IPPROTO_TCP : IPPROTO_UDP;
        ip6h->ip6_hlim = 64;
        inet_pton(AF_INET6, "2001:db8::2", &ip6h->ip6_src);
        inet_pton(AF_INET6, "2606:4700:4700::1111", &ip6h->ip6_dst);
    }

    // transport header
    if(tcp){
        data_start = transport_hdr_start + sizeof(tcphdr);

        auto* tcp_hdr = reinterpret_cast<struct tcphdr*>(transport_hdr_start);
        tcp_hdr->th_sport = htons(53535);   // source port
        tcp_hdr->th_dport = htons(53);      // destination port
        tcp_hdr->th_seq = htonl(1000);      // seq no.
        tcp_hdr->th_ack = htonl(0);         // ack no.
        tcp_hdr->th_off = 5;                // data offset, data starts from byte 5*4 = 20, 5 "words"
        tcp_hdr->th_x2 = 0;                 // reserved bits (idk)
        tcp_hdr->th_flags = TH_SYN;         // tcp flags
        tcp_hdr->th_win = htons(65535);     // how much the receiver is currently willing to accept before waiting for ACK
        tcp_hdr->th_sum = 0;                // checksum
        tcp_hdr->th_urp = 0;                // urgent pointer (idk)
    }
    else{
        data_start = transport_hdr_start + sizeof(udphdr);

        auto* udp_hdr = reinterpret_cast<struct udphdr*>(transport_hdr_start);
        udp_hdr->uh_sport = htons(53535);
        udp_hdr->uh_dport = htons(53);
        udp_hdr->uh_ulen = htons(static_cast<uint16_t>(sizeof(struct udphdr) + data.size()));
        udp_hdr->uh_sum = 0;
    }

    std::memcpy(data_start, data.data(), data.size());

    return UtunPacket{
        .os_header = static_cast<uint32_t>((ipv4) ? AF_INET : AF_INET6),
        .raw_packet = std::move(packet)
    };
}

// ! END


} // namespace utun