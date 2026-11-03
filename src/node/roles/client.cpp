#include "src/node/roles/client.hpp"
#include "src/network/packets/packets.hpp"
#include "src/network/sockets/utun.hpp"
#include "src/network/comms/control.hpp"
#include "src/node/node.hpp"


#include <ifaddrs.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include <quill/LogMacros.h>

namespace asio = boost::asio;


Client::Client(asio::io_context& ioc,
               std::shared_ptr<asio::ip::udp::socket> udp_socketv4,
               std::shared_ptr<asio::ip::udp::socket> udp_socketv6,
               std::shared_ptr<RelaysInfoGlb> known_relays):
    ioc_(ioc),
    udp_socketv4_(std::move(udp_socketv4)),
    udp_socketv6_(std::move(udp_socketv6)),
    running_(false),
    known_relays_(std::move(known_relays)),
    raw_packet_pool_(16384, "client_logger"),
    utun_stream_(ioc_),
    utun_("client_logger"){
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

    if(!utun_.start(true)){
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
    ArenaSlot<utun::RawPacket> raw_packet = raw_packet_pool_.alloc();
    read_packet_utun(std::move(raw_packet));
}


void Client::read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet){
    // TODO: check if this reads whole packet. if it doesn't, how do we make it read the whole packet?
    utun_stream_.async_read_some(
        asio::buffer(raw_packet->payload),
        [me=shared_from_this(), rp = std::move(raw_packet)](const boost::system::error_code& ec, std::size_t bytes_xfer) mutable{
            rp->bytes_received = bytes_xfer;
            me->loop_utun(std::move(rp), ec);
        }
    );
}


void Client::loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec){
    if(ec){
        LOG_ERROR(logger_, "Raw packet read failed: {}", ec.message());
        return;
    }

    // process_raw_packet should come before read_packet to avoid race conditions on seq_id incrementing
    // thread 1: packet1.seq_id = 2
    // thread 2: packet2.seq_id = 1 -> faster because of os scheduling/uncontrolable shit
    process_raw_packet(std::move(raw_packet));

    ArenaSlot<utun::RawPacket> new_raw_packet = raw_packet_pool_.alloc();
    read_packet_utun(std::move(new_raw_packet));
}


// single_threaded: parse packet, query circuit info, increment seq_id, asio::post continue_process_packet and return
void Client::process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet){
    if(!raw_packet->parse_packet()){
        LOG_ERROR(logger_, "Dropping faulty packet from utun.");
        return;
    }

    NetworkTuple nt{
        .src_addr  = raw_packet->src_addr,
        .dest_addr = raw_packet->dest_addr,

        .src_port  = raw_packet->src_port,
        .dest_port = raw_packet->dest_port,
    };

    auto ci = nt_ci_umap_.get(nt);
    if(ci == nullptr) [[unlikely]] {
        ci = make_new_circuit(nt, raw_packet);
        if(ci == nullptr)
            return;
    }

    // update seq_id before returning to read_packet.
    const sequence_id_t seq_id = (*ci->sequence_id_ptr)++;

    // continue_process_raw_packet(std::move(raw_packet), ci);
    asio::post(ioc_, [me = shared_from_this(), rp = std::move(raw_packet), ci, seq_id]() mutable{
        me->continue_process_raw_packet(std::move(rp), ci, seq_id);
    });

    // returns to loop_utun.
}


void Client::continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> ci, sequence_id_t seq_id){
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
            .sequence_id = seq_id,
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

    std::shared_ptr<asio::ip::udp::socket> sock = (relay->endpoint.protocol() == asio::ip::udp::v4())
                                                      ? udp_socketv4_
                                                      : udp_socketv6_;

    // @formatter:off
    sock->async_send_to(
        outgoing,
        relay->endpoint,
        // raw_packet and headers in the lambda to make sure it doesn't get destroyed
        // NOTE: compiler shouldn't theoretically optimize this packet out of the capture list.
        // optimize: no shared_ptrs for 1. packet, 2. headers
        [me=shared_from_this(), outgoing_bytes, keep_alive1 = std::move(raw_packet), keep_alive2 = headers]
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
    // @formatter:on
}


// multithread_care
std::shared_ptr<CircuitInfo> Client::make_new_circuit(NetworkTuple& nt, ArenaSlot<utun::RawPacket>& raw_packet){
    // re-check for circuit_info (if poineer finishes everything before running this function)
    {
        const std::shared_ptr<CircuitInfo> check = nt_ci_umap_.get(nt);
        if(check != nullptr){
            return check;
        }
    }

    std::shared_ptr<OngoingCircuitCalcInfo> prim_state = ci_computing_.get(nt);

    if(prim_state){
        handle_non_pioneers(prim_state, std::move(raw_packet));
        return nullptr;
    }

    // re-check for circuit_info (if a non-pioneer runs above checks after pioneer cleans up everything)
    // first check:
    //      found nothing in nt_ci_umap_
    //      pioneer still doing some work
    // second check:
    //      found nothing in ci_computing_
    //      pioneer completed everything, drained all non-pioneers, deleted nt from ci_computing_
    {
        const std::shared_ptr<CircuitInfo> check = nt_ci_umap_.get(nt);
        if(check != nullptr){
            return check;
        }
    }

    // pioneer packet
    // this function should return nullptr from now on, we std::move(nt)

    // 1. create new OngoingCircuitCalcInfo
    // 2. push pioneer packet to the front of the queue
    // 3. put new OngoingCircuitCalcInfo in ci_computing_ map
    // 4. post compute_drain_new_circuit();

    auto pioneer_state = std::make_shared<OngoingCircuitCalcInfo>(1024, std::move(nt));
    pioneer_state->pending_packets.try_push(std::move(raw_packet));
    auto [non_pioneer_state, pioneer] = ci_computing_.put_if_absent(pioneer_state->nt, pioneer_state);

    // NOT POSSIBLE: both pioneer and a non-pioneer completed above checks concurrently
    // because we're calling make_new_circuit directly from process_raw_packet (process_raw_packet is "single-threaded")
    if(!pioneer){
        LOG_CRITICAL(logger_, "Logic error: \"pioneer\" (maybe) failed to put in ci_computing_.");
        return nullptr;
    }

    asio::post(ioc_, [me = shared_from_this(), ps = pioneer_state]{
        me->compute_drain_new_circuit(ps);
    });
    return nullptr;
}


void Client::compute_drain_new_circuit(std::shared_ptr<OngoingCircuitCalcInfo> cci){
    // TODO: actual circuit computation
    sequence_id_t start_seq = 2385829;
    auto final_ci = std::make_shared<CircuitInfo>(CircuitInfo{
        .circuit_id      = 1232938,
        .sequence_id_ptr = std::make_shared<std::atomic<sequence_id_t>>(2385829),
        .relays          = std::vector<std::shared_ptr<RelayInfo>>{
            std::make_shared<RelayInfo>(RelayInfo{
                .session_id = 12321344,
                .endpoint   = asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 6000),
            })
        },
        .reorder_buffer = std::make_shared<ReorderBuffer<ArenaSlot<IncomingCell>, sequence_id_t>>(2048, start_seq) // fixme: remove 2048
    });
    sid_ci_umap_.put(12321344, final_ci);


    // After computing circuit:

    // 1. update OngoingCircuitCalcInfo's ci to the actual ci
    // 2. cci->is_building = false;

    // steps 1 and 2 prevent this problem:
    //      * non-pioneer (in handle_non_pioneers()) pushing into the queue just as drain_new_circuit_packets() finishes.

    // 3. drain waiting packets         -> updates nt_ci_umap_
    // 4. erase from ci_computing_

    cci->ci = final_ci;
    cci->is_building.store(false, std::memory_order_release);
    drain_new_circuit_packets(cci);
    ci_computing_.erase(cci->nt);
}


void Client::handle_non_pioneers(const std::shared_ptr<OngoingCircuitCalcInfo>& curr_state, ArenaSlot<utun::RawPacket> raw_packet){
    if(!curr_state->pending_packets.try_push(std::move(raw_packet))){
        LOG_ERROR(logger_, "Failed to push raw_packet into queue while circuit info is being computed.");
        return;
    }

    // edge-case: if circuit-making finished right as we pushed
    // we can't trust drain_new_circuit_packets() to drain our packet anymore
    if(!curr_state->is_building.load(std::memory_order_acquire)){
        // uses updated circuit info (from curr_state->ci, compute_drain_new_circuit updated this before setting is_building = false)
        if(!curr_state->ci){
            LOG_CRITICAL(logger_, "curr_state->ci is nullptr in handle_non_pioneers()");
            return;
        }
        // call compute_drain_new_circuit
        // NOTE: MUTEX ON HOT PATH. no way to resolve this
        drain_new_circuit_packets(curr_state);
    }
}


void Client::drain_new_circuit_packets(const std::shared_ptr<OngoingCircuitCalcInfo>& state){
    // Note: no other alternative, we should use mutex for this
    // banged my head against the wall for 5 hours
    std::scoped_lock lock(ci_computing_drain_mtx_);

    while(auto popped_pkt = state->pending_packets.try_pop()){
        // Note: since handle_new_pioneer() also updates the same state->ci's sequence id,
        // even if the poineer updates the nt_ci_umap_, the seq_id gets incremented.
        sequence_id_t seq_id = (*state->ci->sequence_id_ptr)++;
        asio::post(
            ioc_,
            [me = shared_from_this(), temp_pkt = std::move(*popped_pkt), circuit_info = state->ci, seq_id]() mutable{
                me->continue_process_raw_packet(std::move(temp_pkt), circuit_info, seq_id);
            }
        );
    }

    nt_ci_umap_.put_if_absent(state->nt, state->ci);
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


void Client::process_incoming_packet(ArenaSlot<IncomingCell> packet){
    if(!packet){
        LOG_WARNING(logger_, "Recieved empty packet.");
        return;
    }

    if(!parse_incoming_packet(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet.");
        return;
    }

    if(packet->cid == static_cast<circuit_id_t>(-1)){
        handle_control_from_relay(packet);
        return;
    }

    insert_into_rob(std::move(packet));
}


/*
incoming packet:
    route_flag
    session_id
    {thdr, phdr, payload}
*/
[[nodiscard]] bool Client::parse_incoming_packet(const ArenaSlot<IncomingCell>& packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(session_id_t)){
        return false;
    }

    packet->sid = 0;
    size_t loops = sizeof(session_id_t) / sizeof(uint8_t);
    for(size_t i = 0; i < loops; i++){
        uint8_t byte = static_cast<session_id_t>(packet->payload[i + sizeof(RoutingFlag)]);
        size_t shift = 8 * (loops - i - 1);
        packet->sid |= (byte << shift);
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

    // todo: actual ip version, packet parsing, start_offset etc.
    packet->ip_version_macos = htonl(AF_INET);

    return true;
}


void Client::handle_control_from_relay(const ArenaSlot<IncomingCell>& packet) const{
    constexpr size_t header_len = sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ;
    if(packet->bytes_received < header_len + CONTROL_HDR_SZ){
        LOG_ERROR(logger_, "Dropping control packet from relay: size too small ({})", packet->bytes_received);
        return;
    }

    ControlHeader chdr{};
    std::memcpy(&chdr, packet->payload.data() + header_len, CONTROL_HDR_SZ);

    const uint8_t* body_ptr = packet->payload.data() + header_len + CONTROL_HDR_SZ;
    const size_t body_len = packet->bytes_received - (header_len + CONTROL_HDR_SZ);

    std::vector<uint8_t> payload_data(body_ptr, body_ptr + body_len);

    if(chdr.flags == static_cast<uint8_t>(ControlMsgType::RELAY_HANDSHAKE_RESP) && known_relays_){
        Node::resume_establishing_connection(packet->sid, std::move(payload_data), known_relays_);
        return;
    }
}


void Client::insert_into_rob(ArenaSlot<IncomingCell> packet){
    // todo: complete this
    auto circuit_info = sid_ci_umap_.get(packet->sid);
    if(!circuit_info){
        LOG_WARNING(logger_, "Recieved incoming packet with unknown cid: {}", packet->cid);
        return;
    }

    const auto reorder_buffer = circuit_info->reorder_buffer;
    if(!reorder_buffer->insert_try_drain(
            packet->seq_id,
            std::move(packet),
            [me=shared_from_this()](sequence_id_t seq_id, ArenaSlot<IncomingCell> pkt){
                me->write_to_utun(seq_id, std::move(pkt));
            }
        )
    ){
        LOG_ERROR(logger_, "Reorder buffer insert failed. Redo this log message with clearer error.");
    }
}


void Client::write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet){
    if(!packet || packet->payload_bytes == 0){
        return;
    }

    // todo: this properly
    asio::async_write(
        utun_stream_,
        asio::buffer(packet->payload.data(), packet->payload_bytes),
        [me = shared_from_this(), pkt = std::move(packet), seq_id]
    (const boost::system::error_code& ec, size_t /*bytes_transferred*/) mutable{
            if(ec){
                LOG_ERROR(me->logger_, "Failed to write seq_id {} to utun: {}", seq_id, ec.message());
            }
        }
    );
}
