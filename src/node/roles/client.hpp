#pragma once

#include "src/network/sockets/utun.hpp"
#include "src/network/packets/cell.hpp"
#include "src/network/packets/packets.hpp"
#include "src/node/node_utils.hpp"
#include "src/node/buffers/reorder_buffer.hpp"
#include "src/node/buffers/arena_allocator.hpp"

#include <vector>

#include <boost/asio.hpp>
#include <boost/container_hash/hash.hpp>

#include <quill/Frontend.h>

namespace asio = boost::asio;

/*
* Client proc:

connect to control_server
setup tun
analyze how many exits we need:
    1. for browser traffic, we can set up different exits based on the websites they're visiting
    2. for other apps, query for best exit and use that
query for relays for each exit node from control_server
if nat prohibits: connect to turn 
connect to those relays using stun/turn
set up 1 hop connection to exit
send traffic
send analytics to control_server periodically


what should we communicate with the control_server:
1. upload/download speeds
2. for demo purposes: what exits are we using, data being sent to each exit, circuit information for
    each client_ -> exit_ (like what relays we're using, data being sent to those relays etc)


*/

struct NetworkTuple{
    asio::ip::address src_addr;
    asio::ip::address dest_addr;

    uint16_t src_port;
    uint16_t dest_port;


    bool operator==(const NetworkTuple& other) const{
        return (src_addr == other.src_addr) &&
               (dest_addr == other.dest_addr) &&
               (src_port == other.src_port) &&
               (dest_port == other.dest_port);
    }
};


struct RelayInfo{
    session_id_t session_id;
    asio::ip::udp::endpoint endpoint;
    // relay performance
    // sh_cr
};


struct CircuitInfo{
    circuit_id_t circuit_id;
    std::shared_ptr<std::atomic<sequence_id_t>> sequence_id_ptr;
    std::vector<std::shared_ptr<RelayInfo>> relays; // OPTIMIZE: no vector. use ring buffer (organized by other thread)
    // sh_ce
    std::shared_ptr<ReorderBuffer<ArenaSlot<IncomingCell>, sequence_id_t>> reorder_buffer;
};


struct OngoingCircuitCalcInfo{
    std::atomic<bool> is_building;
    ArenaSlotQueue<utun::RawPacket> pending_packets;


    explicit OngoingCircuitCalcInfo(const size_t queue_sz):
        is_building(true),
        pending_packets(queue_sz){}
};


template<>
struct std::hash<NetworkTuple>{
    std::size_t operator()(const NetworkTuple& tuple) const noexcept{
        std::size_t seed = 0;

        boost::hash_combine(seed, std::hash<std::string>{}(tuple.src_addr.to_string()));
        boost::hash_combine(seed, std::hash<std::string>{}(tuple.dest_addr.to_string()));

        boost::hash_combine(seed, std::hash<uint16_t>{}(tuple.src_port));
        boost::hash_combine(seed, std::hash<uint16_t>{}(tuple.dest_port));

        return seed;
    }
};


class Client : public std::enable_shared_from_this<Client>{
public:
    Client(asio::io_context& ioc, asio::ip::udp::socket& udp_socketv4, asio::ip::udp::socket& udp_socketv6);


    ~Client();


    Client(const Client& other) = delete;


    Client& operator=(const Client& other) = delete;


    [[nodiscard]] bool start();


    void stop();


    void process_incoming_packet(ArenaSlot<IncomingCell> packet);

private:
    asio::io_context& ioc_;
    asio::ip::udp::socket& udp_socketv4_;
    asio::ip::udp::socket& udp_socketv6_;

    std::atomic<bool> running_;

    ArenaAllocator<utun::RawPacket> raw_packet_pool_;

    asio::posix::stream_descriptor utun_stream_;
    std::atomic<int> utun_sockfd_ = -1;
    Utun utun_;

    RCU_UMap<NetworkTuple, std::shared_ptr<CircuitInfo>> nt_ci_umap_;
    asio::strand<asio::io_context::executor_type> ci_computing_strand_;
    RCU_UMap<NetworkTuple, std::shared_ptr<OngoingCircuitCalcInfo>> ci_computing_;

    RCU_UMap<circuit_id_t, std::shared_ptr<CircuitInfo>> cid_ci_umap_;

    quill::Logger* logger_{nullptr};


    inline void start_listening_utun();


    void read_packet(ArenaSlot<utun::RawPacket> raw_packet);


    void loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec);


    void process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet);


    void continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> ci);


    void make_new_circuit(const NetworkTuple& nt, ArenaSlot<utun::RawPacket> raw_packet);


    void handle_non_pioneers(const std::shared_ptr<OngoingCircuitCalcInfo>& curr_state, const NetworkTuple& nt, ArenaSlot<utun::RawPacket> raw_packet);


    void drain_non_pioneers(const std::shared_ptr<OngoingCircuitCalcInfo>& state, std::shared_ptr<CircuitInfo> ci);


    std::shared_ptr<RelayInfo> choose_relay(const std::shared_ptr<CircuitInfo>& ci);


    [[nodiscard]] static bool parse_incoming_packet(const ArenaSlot<IncomingCell>& packet);


    void insert_into_rob(ArenaSlot<IncomingCell> packet);


    void write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet);
};
