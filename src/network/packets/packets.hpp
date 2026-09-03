#pragma once
#include <cstdint>
#include <boost/asio.hpp>
// #include <boost/asio/awaitable.hpp>

namespace asio = boost::asio;


namespace utun{


class RawPacket{
public:
    uint32_t family_hdr = -1;               // 4 byte macos field
    size_t ip_hdr_sz = -1;
    size_t total_packet_len = -1;
    std::vector<uint8_t> payload;
    asio::ip::address src_addr, dest_addr;
    uint16_t src_port = -1, dest_port = -1;

    asio::awaitable<void> async_listen_utun(std::shared_ptr<asio::posix::stream_descriptor> utun_stream, 
        std::function<void(boost::system::error_code)> handler);

private:
    bool parse_macos_header(asio::posix::stream_descriptor& utun_stream);
    bool parse_ip_header(asio::posix::stream_descriptor& utun_stream);
    bool get_payload(asio::posix::stream_descriptor& utun_stream);
    bool process_packet();

};


}