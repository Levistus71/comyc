#pragma once
#include <utility>

namespace UTUN{

struct UtunPacket{
    uint32_t os_header;
    std::vector<uint8_t> raw_packet;
};

// ! START: remove this, temporary
std::pair<int,int> dummy_tun();
void simulate_utun(int write_fd);
// ! END

} // namespace UTUN
