#pragma once

#include "src/network/packets/cell.hpp"
#include "src/network/packets/packets.hpp"
#include "src/node/node_utils.hpp"
#include "src/node/node.hpp"

#include <vector>
#include <shared_mutex>

#include <boost/asio.hpp>
#include <boost/container_hash/hash.hpp>
#include <boost/asio/experimental/channel.hpp>

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


// ! experimental features: channel
using CircuitChannel = asio::experimental::channel<
    void(boost::system::error_code, std::shared_ptr<CircuitInfo>)
>;


class Client : public std::enable_shared_from_this<Client>{
public:
    Client(asio::io_context& ioc, asio::ip::udp::socket& udp_socket);


    ~Client();


    void start();


    // auto stop();

    void process_incoming_packet(std::shared_ptr<IncomingCell> packet);

private:
    asio::io_context& ioc_;
    asio::ip::udp::socket& udp_socket_;

    asio::posix::stream_descriptor utun_stream_;
    std::atomic<int> utun_sockfd_ = -1;

    RCU_UMap<NetworkTuple, CircuitInfo> nt_ci_umap_;
    asio::strand<asio::io_context::executor_type> ci_computing_strand_;
    std::unordered_map<NetworkTuple, std::shared_ptr<CircuitChannel>> ci_computing_; // stranded


    void start_utun();


    void read_packet(std::shared_ptr<utun::RawPacket> raw_packet);


    void loop_utun(std::shared_ptr<utun::RawPacket> raw_packet, boost::system::error_code const& ec);


    asio::awaitable<void> process_raw_packet(std::shared_ptr<utun::RawPacket> raw_packet);


    asio::awaitable<std::shared_ptr<CircuitInfo>> make_new_circuit(const NetworkTuple& nt);


    asio::awaitable<std::shared_ptr<CircuitInfo>> make_new_circuit_helper(const NetworkTuple& nt);


    std::shared_ptr<RelayInfo> choose_relay(std::shared_ptr<CircuitInfo> ci);
};
