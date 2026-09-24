#include "src/node/roles/client.hpp"
#include "src/network/packets/packets.hpp"
#include "src/network/sockets/utun.hpp"

#include <random>
#include <string>
#include <vector>
#include <iostream>

#include <boost/asio.hpp>

#include <quill/LogMacros.h>

namespace asio = boost::asio;


Client::Client(asio::io_context& ioc, asio::ip::udp::socket& udp_socketv4, asio::ip::udp::socket& udp_socketv6):
    ioc_(ioc),
    udp_socketv4_(udp_socketv4),
    udp_socketv6_(udp_socketv6),
    utun_stream_(ioc_),
    ci_computing_strand_(asio::make_strand(ioc_)){
    logger_ = quill::Frontend::get_logger("client_logger");
}


Client::~Client(){
    if(running_.load()){
        stop();
    }
}


[[nodiscard]] bool Client::start(){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "Called start() more than once.");
        return false;
    }

    // todo: connect_control_server(), connect_peers(), utun_.add_del_route() etc;
    if(!utun_.add_del_route(true,
                            asio::ip::make_address("8.8.8.8"),
                            asio::ip::make_address("255.255.255.255"),
                            asio::ip::make_address("192.168.0.1"))){
        LOG_ERROR(logger_, "Failed to add (relay ip) to utun routes.");
        return false;
    }

    if(!utun_.start()){
        LOG_ERROR(logger_, "Failed to start utun.");
        return false;
    }
    LOG_INFO(logger_, "[UTUN] Started successfully.");

    utun_sockfd_ = utun_.get_fd();

    boost::system::error_code ec;
    if(utun_stream_.assign(utun_sockfd_, ec)){
        LOG_ERROR(logger_, "Failed to convert utun_sockfd_ to asio stream_descriptor.");
        return false;
    }

    start_listening_utun();

    LOG_INFO(logger_, "Started successfully.");
    return true;
}


inline void Client::start_listening_utun(){
    std::shared_ptr<utun::RawPacket> raw_packet = std::make_shared<utun::RawPacket>();
    read_packet(raw_packet);
}


void Client::read_packet(const std::shared_ptr<utun::RawPacket>& raw_packet){
    // TODO: check if this reads whole packet. if it doesn't, how do we make it read the whole packet?
    utun_stream_.async_read_some(
        asio::buffer(raw_packet->payload),
        [me=shared_from_this(), raw_packet](const boost::system::error_code& ec, std::size_t bytes_xfer){
            raw_packet->bytes_received = bytes_xfer;
            me->loop_utun(raw_packet, ec);
        }
    );
}


void Client::loop_utun(const std::shared_ptr<utun::RawPacket>& raw_packet, boost::system::error_code const& ec){
    if(ec){
        LOG_ERROR(logger_, "Raw packet read failed: {}", ec.message());
        return;
    }

    std::shared_ptr<utun::RawPacket> new_raw_packet = std::make_shared<utun::RawPacket>();
    read_packet(new_raw_packet);

    // process_raw_packet(raw_packet);
    asio::co_spawn(
        ioc_,
        process_raw_packet(raw_packet),
        asio::detached
    );
}


// multithread_care
asio::awaitable<void> Client::process_raw_packet(std::shared_ptr<utun::RawPacket> raw_packet){
    if(!raw_packet->parse_packet()){
        LOG_ERROR(logger_, "Dropping faulty packet.");
        co_return;
    }

    // map: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id}
    // {circuit_id} : {SH_CE, vector<session_id>}
    // {session_id} : {SH_CR, circuit_id, socket_info}

    /*

    outbound: {source_ip, source_port, destination_ip, destination_port} : {circuit_id, sequence_id, SH_CE, vector<session_id,SH_CR,socket_info,relay_performance>}
    inbound: {session_id} : {SH_CR, SH_CE, jitter_buffer addr}

    */

    NetworkTuple nt{
        .src_addr  = raw_packet->src_addr,
        .dest_addr = raw_packet->dest_addr,

        .src_port  = raw_packet->src_port,
        .dest_port = raw_packet->dest_port,
    };

    auto ci = nt_ci_umap_.get(nt);
    if(ci == nullptr){
        ci = co_await make_new_circuit(nt);
    }

    const auto relay = choose_relay(ci);

    const auto app_internal_bytes = raw_packet->bytes_received - FAMILY_HDR_UTUN_SZ;
    auto headers = std::make_shared<ClientFullHeaders>(ClientFullHeaders{
        .route_flag = RoutingFlag::CLIENT_TO_RELAY,
        .session_id = relay->session_id,
        .thdr{
            .circuit_id   = ci->circuit_id,
            .frame_len    = 1,
            .flags        = 0,
            .payload_tier = PayloadTier::TIER_1024
        },
        .phdr{
            .sequence_id = (*ci->sequence_id_ptr)++,
            .ip_protocol = 0,
            .packet_id   = 0,
            .payload_len = static_cast<uint16_t>(app_internal_bytes),
            .frag_index  = 0,
            .frag_total  = 0
        }
    });

    // todo: encrypt sh_ce, sh_cr
    size_t outgoing_bytes = sizeof(ClientFullHeaders) + app_internal_bytes;
    const std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(headers.get(), sizeof(ClientFullHeaders)),
        asio::buffer(raw_packet->payload.data() + FAMILY_HDR_UTUN_SZ, app_internal_bytes)
    };

    asio::ip::udp::socket& sock = (relay->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

    sock.async_send_to(
        outgoing,
        relay->endpoint,
        // raw_packet and headers in the lambda to make sure it doesn't get destroyed
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        // optimize: no shared_ptrs for 1. packet, 2. headers
        [me=shared_from_this(), outgoing_bytes, keep_alive1 = raw_packet, keep_alive2 = headers, keep_alive3 = outgoing, keep_alive4 = relay]
    (const boost::system::error_code& ec, std::size_t bytes_xfer){
            if(ec){
                LOG_ERROR(me->logger_, "[TUN Worker] Send failed: {}", ec.message());
                return;
            }
            if(bytes_xfer != outgoing_bytes){
                LOG_ERROR(me->logger_, "[TUN Worker] Bytes sent mismatch: UDP socket fail?");
                return;
            }
        }
    );
}


// multithread_care
asio::awaitable<std::shared_ptr<CircuitInfo>> Client::make_new_circuit(const NetworkTuple& nt){
    co_return co_await asio::co_spawn(
        ci_computing_strand_,
        make_new_circuit_helper(nt),
        asio::use_awaitable
    );
}


// stranded
asio::awaitable<std::shared_ptr<CircuitInfo>> Client::make_new_circuit_helper(const NetworkTuple& nt){
    // NOT PIONEER PACKETS
    if(const auto it = ci_computing_.find(nt); it != ci_computing_.end()){
        const auto chan = it->second;
        co_return co_await chan->async_receive(asio::use_awaitable);
    }
    // if already completed when we were competing for the strand
    {
        auto t = nt_ci_umap_.get(nt);
        if(t != nullptr){
            co_return t;
        }
    }

    // PIONEER PACKET
    ci_computing_[nt] = std::make_shared<CircuitChannel>(ci_computing_strand_.get_inner_executor(), 100);

    // TODO: co_await async_compute_ci(nt);
    auto ci = CircuitInfo{
        .circuit_id      = 1232938,
        .sequence_id_ptr = std::make_shared<std::atomic<sequence_id_t>>(23412),
        .relays          = std::vector<std::shared_ptr<RelayInfo>>{
            std::make_shared<RelayInfo>(RelayInfo{
                .session_id = 12321344,
                .endpoint   = asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 6000),
            })
        }
    };
    nt_ci_umap_.put(nt, std::move(ci));
    auto val = nt_ci_umap_.get(nt);

    const auto active_chan = std::move(ci_computing_[nt]);
    ci_computing_.erase(nt);
    while(active_chan->ready()){
        active_chan->try_send(boost::system::error_code{}, val);
    }
    active_chan->close();

    co_return val;
}


std::shared_ptr<RelayInfo> Client::choose_relay(const std::shared_ptr<CircuitInfo>& ci){
    // TODO: scheduling
    return ci->relays[0];
}


void Client::stop(){
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "Called stop() more than once.");
        return;
    }

    utun_.stop();

    // TODO: signal relays/exit
}


void Client::process_incoming_packet(std::shared_ptr<IncomingCell> packet){
    if(!parse_incoming_packet(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet.");
    }

    async_write_to_utun(packet);
}


/*
incoming packet:
    route_flag
    session_id
    {thdr, phdr, payload}
*/
[[nodiscard]] bool Client::parse_incoming_packet(std::shared_ptr<IncomingCell> packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(session_id_t)){
        return false;
    }

    packet->sid = 0;
    size_t loops = sizeof(session_id_t) / sizeof(uint8_t);
    for(size_t i = 0; i < loops; i++){
        uint8_t byte = static_cast<session_id_t>(packet->payload[i + sizeof(RoutingFlag)]);
        size_t shift = 8 * (loops - i - 1);
        packet->cid |= (byte << shift);
    }

    // todo: decrypt_using_sh_cr()
    // todo: decrypt_using_sh_ce()

    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(session_id_t) + sizeof(circuit_id_t)){
        return false;
    }

    packet->cid = 0;
    loops = sizeof(circuit_id_t) / sizeof(uint8_t);
    for(size_t i = 0; i < loops; i++){
        uint8_t byte = static_cast<circuit_id_t>(packet->payload[i + sizeof(RoutingFlag) + sizeof(session_id_t)]);
        size_t shift = 8 * (loops - i - 1);
        packet->cid |= (byte << shift);
    }

    // todo: actual packet parsing, start_offset etc.
    return true;
}


void Client::async_write_to_utun(std::shared_ptr<IncomingCell> packet){
    // todo: complete this
    return;
}
