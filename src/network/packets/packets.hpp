#pragma once

#include <cstdint>
#include <array>

#include <boost/asio.hpp>

namespace asio = boost::asio;


namespace utun{

constexpr size_t RAW_PACKET_MAX_SZ = 2000;

class RawPacket{
public:
    std::array<uint8_t, RAW_PACKET_MAX_SZ> payload;
    size_t bytes_received = 0;              // populated by usr

    uint32_t family_hdr = 0;                // 4 byte macos field
    size_t ip_hdr_sz = 0;
    size_t total_packet_len = 0;

    asio::ip::address src_addr;
    asio::ip::address dest_addr;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;

    [[nodiscard]] bool parse_packet();

private:
    [[nodiscard]] bool parse_macos_header();
    [[nodiscard]] bool parse_headers();
};


}