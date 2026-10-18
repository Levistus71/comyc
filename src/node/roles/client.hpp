#pragma once

#include "src/network/sockets/utun.hpp"
#include "src/network/packets/cell.hpp"
#include "src/network/packets/packets.hpp"
#include "src/node/node_utils.hpp"
#include "src/node/buffers/arena_allocator.hpp"

#include <utility>

#include <boost/asio.hpp>

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


struct OngoingCircuitCalcInfo{
    std::atomic<bool> is_building;
    ArenaSlotQueue<utun::RawPacket> pending_packets;
    std::shared_ptr<CircuitInfo> ci;
    NetworkTuple nt;


    explicit OngoingCircuitCalcInfo(const size_t queue_sz, NetworkTuple nt):
        is_building(true),
        pending_packets(queue_sz),
        ci{nullptr},
        nt{std::move(nt)}{}
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

    // outgoing
    RCU_UMap<NetworkTuple, std::shared_ptr<CircuitInfo>> nt_ci_umap_;
    RCU_UMap<NetworkTuple, std::shared_ptr<OngoingCircuitCalcInfo>> ci_computing_;
    std::mutex ci_computing_drain_mtx_;
    std::recursive_mutex ci_computing_ni_ci_update_rec_mtx_;

    // incoming
    RCU_UMap<sequence_id_t, std::shared_ptr<CircuitInfo>> sid_ci_umap_;

    quill::Logger* logger_{nullptr};


    inline void start_listening_utun();


    void read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet);


    void loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec);


    void process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet);


    void continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> ci, sequence_id_t seq_id);


    std::shared_ptr<CircuitInfo> make_new_circuit(NetworkTuple& nt, ArenaSlot<utun::RawPacket>& raw_packet);


    void compute_drain_new_circuit(std::shared_ptr<OngoingCircuitCalcInfo> cci);


    void handle_non_pioneers(const std::shared_ptr<OngoingCircuitCalcInfo>& curr_state, ArenaSlot<utun::RawPacket> raw_packet);


    void drain_new_circuit_packets(const std::shared_ptr<OngoingCircuitCalcInfo>& state);


    std::shared_ptr<RelayInfo> choose_relay(const std::shared_ptr<CircuitInfo>& ci);


    [[nodiscard]] static bool parse_incoming_packet(const ArenaSlot<IncomingCell>& packet);


    void insert_into_rob(ArenaSlot<IncomingCell> packet);


    void write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet);
};
