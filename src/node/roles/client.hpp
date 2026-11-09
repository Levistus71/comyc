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


// forward declaration of node class
class Node;


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
    friend struct CircuitInfo;


    Client(asio::io_context& ioc,
           std::shared_ptr<asio::ip::udp::socket> udp_socketv4,
           std::shared_ptr<asio::ip::udp::socket> udp_socketv6,
           std::shared_ptr<RelaysInfoGlb> known_relays);


    ~Client();


    Client(const Client& other) = delete;


    Client& operator=(const Client& other) = delete;


    [[nodiscard]] asio::awaitable<bool> start(bool hijack_system_traffic, bool act_dead = false);


    void stop();


    void process_incoming_packet(ArenaSlot<IncomingCell> packet);


    //
    asio::awaitable<bool> make_new_circuit(std::optional<NetworkTuple> nt = std::nullopt);


    struct Settings{
        static constexpr uint64_t HIGH_USAGE_THRESHOLD = 300;
        static constexpr uint64_t DEFAULT_NUM_ENTRY_RELAYS = 2;

        static_assert(DEFAULT_NUM_ENTRY_RELAYS < MAX_RELAYS_PER_CIRCUIT, "Default number of entry relays too large.");

        static constexpr uint64_t ARENA_SLOTS = 16384;
    };

private:
    asio::io_context& ioc_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv4_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv6_;

    std::atomic<bool> running_;

    std::shared_ptr<RelaysInfoGlb> known_relays_;
    std::shared_ptr<CircuitInfo> default_ci_;
    asio::ip::address_v4 default_vpn_v4_;
    asio::ip::address_v6 default_vpn_v6_;

    ArenaAllocator<utun::RawPacket> raw_packet_pool_;

    asio::posix::stream_descriptor utun_stream_;
    std::atomic<int> utun_sockfd_ = -1;
    Utun utun_;

    // outgoing
    RCU_UMap<NetworkTuple, std::shared_ptr<CircuitInfo>> nt_ci_umap_;
    RCU_UMap<NetworkTuple, std::shared_ptr<OngoingCircuitCalcInfo>> ci_computing_;
    std::mutex ci_computing_drain_mtx_;

    // incoming
    RCU_UMap<sequence_id_t, std::shared_ptr<CircuitInfo>> sid_ci_umap_;
    // utun
    std::mutex utun_write_mtx_;
    std::deque<ArenaSlot<IncomingCell>> utun_write_queue_;
    bool utun_writing_{false};
    std::atomic<size_t> relay_rr_counter_{0};   // todo: move this to per-circuit counter

    quill::Logger* logger_{nullptr};


    inline void start_listening_utun();


    void read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet);


    void loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec);


    void process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet);


    void continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> ci, sequence_id_t seq_id);


    std::shared_ptr<CircuitInfo> track_new_nt(NetworkTuple& nt, ArenaSlot<utun::RawPacket>& raw_packet);


    static std::vector<uint8_t> make_relay_setup_exit_req_packet(session_id_t sid,
                                                                 const asio::ip::udp::endpoint& exit_ep,
                                                                 txn_id_t txn_id,
                                                                 circuit_id_t circuit_id);


    static std::vector<uint8_t> make_exit_handshake_packet(session_id_t sid,
                                                           circuit_id_t cid,
                                                           txn_id_t txn_id,
                                                           sequence_id_t our_start_seq,
                                                           const std::vector<std::shared_ptr<RelayInfo>>& selected_relays,
                                                           const asio::ip::address_v4& our_address_v4,
                                                           uint16_t our_port,
                                                           const asio::ip::address_v4& dest_address_v4,
                                                           uint16_t dest_port,
                                                           bool default_circuit);


    void compute_new_nt_ci(std::shared_ptr<OngoingCircuitCalcInfo> cci);


    void handle_non_pioneers(const std::shared_ptr<OngoingCircuitCalcInfo>& curr_state, ArenaSlot<utun::RawPacket> raw_packet);


    void drain_new_nt_packets(const std::shared_ptr<OngoingCircuitCalcInfo>& state);


    std::shared_ptr<RelayInfo> choose_relay(const std::shared_ptr<CircuitInfo>& ci);


    [[nodiscard]] static bool parse_incoming_packet(const ArenaSlot<IncomingCell>& packet);


    void handle_control_from_relay(const ArenaSlot<IncomingCell>& packet) const;


    void insert_into_rob(ArenaSlot<IncomingCell> packet);


    void write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet);


    void do_write_utun(std::unique_lock<std::mutex> lock, sequence_id_t seq_id);


    void simulate_system_traffic();
};
