#pragma once
#include <src/network/packets/cell.hpp>
#include <src/network/packets/packets.hpp>
#include <src/network/sockets/utun.hpp>
#include <src/node/buffers/arena_allocator.hpp>
#include <src/node/node_utils.hpp>

#include <boost/asio.hpp>

#include <quill/Frontend.h>

namespace asio = boost::asio;


/*

1. Frame from relay
2. We get the app_data information: APP_Internal = APP_InternetProtocol + APP_TransportProtocol + APP_Encrypt(APP_Payload)
* APP_InternetProtocol contains client's local ip and port.
3. We can directly write APP_Internal to destination socket. The OS replaces client's local ip and port with Exit's information
before sending. After receiving the frame from the destination, the OS replaces the destination from the recevied frame to
client's local ip and port.

In short: the OS kinda understands that we are *routing* and are not a client. We don't need to change the raw
APP_InternetProtocol and replace it with our own ip. We need to maintain (client's local ip + port, circuit_id)
mapping in exit.

Caveat: We can't write the APP_Internal to the socket (connect() etc). We need to write the raw frame directly to the device.

*/

/*

# 1. Enable IP forwarding in the Linux Kernel
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Create the TUN interface
sudo ip tuntap add mode tun dev tun0

# 3. Assign a private IP address and subnet to the TUN interface (exit_gateway_ or exit_dummy_ip_addr_)
sudo ip addr add 10.8.0.1/24 dev tun0

# 4. Bring the TUN interface UP
sudo ip link set dev tun0 up

# 5. Set up NAT (Masquerading) via iptables outbound on your physical network card (e.g., eth0)
# tells the OS that exit's acting like a "router" instead of a client, (hides private {exit_dummy_ip_addr_})
# source network address translation (SNAT). when a packet is going out of exit, os intercepts it, replaces
# {exit_dummy_ip_addr_} with eth0's ip and then sends it off. when it recieves, it replaces eth0's ip back to
# {exit_dummy_ip_addr_}.
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 6. Allow packet forwarding between tun0 and eth0
# RELATED,ESTABLISHED: incoming connections set up from outgoing traffic (step 5.) are allowed, nothing else
# like a firewall, the os automatically blocks unsolicited traffic, only accepts traffic that we {exit} initiated
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT


we don't need to add/delete routes, just set up this interface and write/read from it.
*/

class Exit : public std::enable_shared_from_this<Exit>{
public:
    Exit(asio::io_context& ioc,
         std::shared_ptr<asio::ip::udp::socket> udp_socketv4,
         std::shared_ptr<asio::ip::udp::socket> udp_socketv6,
         const std::shared_ptr<RelaysInfoGlb>& relays_info_glb,
         const std::shared_ptr<network_stats::StatsReporter>& stats_reporter);


    ~Exit();


    [[nodiscard]] bool start();


    void stop();


    void process_incoming_packet(ArenaSlot<IncomingCell> packet, asio::ip::udp::endpoint sender_endpoint);


    struct Settings{
        static constexpr uint64_t REORDER_BUFFER_SIZE = 2048;
    };

private:
    asio::io_context& ioc_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv4_;
    std::shared_ptr<asio::ip::udp::socket> udp_socketv6_;

    std::atomic<bool> running_;

    ArenaAllocator<utun::RawPacket> raw_packet_pool_;

    asio::strand<asio::io_context::executor_type> utun_strand_;
    asio::posix::stream_descriptor utun_stream_;
    std::atomic<int> utun_sockfd_;
    Utun utun_;

    quill::Logger* logger_{nullptr};
    std::shared_ptr<network_stats::StatsReporter> stats_reporter_;

    // from destination to client
    RCU_UMap<NetworkTuple, std::shared_ptr<CircuitInfo>> nt_ci_umap_;
    RCU_UMap<SrcAddrNetworkTuple, std::shared_ptr<CircuitInfo>> sant_ci_umap_;

    // from client to destination
    RCU_UMap<circuit_id_t, std::shared_ptr<CircuitInfo>> cid_ci_umap_;

    // utun
    std::deque<ArenaSlot<IncomingCell>> utun_write_queue_;
    bool utun_writing_{false};
    std::atomic<size_t> relay_rr_counter_{0};

    // shutdown
    std::shared_ptr<RelaysInfoGlb> glb_;


    void start_listening_utun();


    void read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet);


    void loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec);


    void process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet);


    void continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> circuit_info, sequence_id_t seq_id);


    std::shared_ptr<RelayInfo> choose_relay(const std::shared_ptr<CircuitInfo>& ci);


    [[nodiscard]] bool parse_headers_incoming_packet(const ArenaSlot<IncomingCell>& packet);


    void handle_control_from_relay(ArenaSlot<IncomingCell> packet, const asio::ip::udp::endpoint& relay_endpoint);


    static std::vector<uint8_t> make_exit_handshake_resp_packet(const ControlHeader& chdr,
                                                                circuit_id_t cid,
                                                                sequence_id_t seq_id,
                                                                uint64_t reorder_buffer_size,
                                                                const std::array<uint8_t, 32>& pubkey);


    asio::awaitable<void> send_shutdown_syn(circuit_id_t circuit_id, std::shared_ptr<CircuitInfo> circuit_info);


    std::vector<uint8_t> make_shutdown_syn_packet(circuit_id_t circuit_id, txn_id_t txn_id);


    void insert_into_rob(ArenaSlot<IncomingCell> packet);


    void write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet);


    void do_write_utun(sequence_id_t seq_id);
};
