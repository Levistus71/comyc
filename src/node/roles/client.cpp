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
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <quill/LogMacros.h>

namespace asio = boost::asio;


void CircuitInfo::touch(const std::shared_ptr<Client>& client_ptr) const{
    if(!client_ptr || !activity_counter)
        return;

    activity_counter->record_use();

    if(activity_counter->dont_create_new_circuit.load(std::memory_order_acquire))
        return;

    if(activity_counter->get_rate_in_window() > Client::Settings::HIGH_USAGE_THRESHOLD){
        bool expected = false;
        if(activity_counter->new_circuit_queued.compare_exchange_strong(expected, true, std::memory_order_acq_rel)){
            activity_counter->dont_create_new_circuit.store(true, std::memory_order_release);

            auto net_type = this->nt;

            asio::co_spawn(
                client_ptr->ioc_,
                [client_keep_alive = client_ptr, net_type]() -> asio::awaitable<void>{
                    co_await client_keep_alive->make_new_circuit(net_type);
                },
                asio::detached
            );
        }
    }
}


Client::Client(asio::io_context& ioc,
               std::shared_ptr<asio::ip::udp::socket> udp_socketv4,
               std::shared_ptr<asio::ip::udp::socket> udp_socketv6,
               std::shared_ptr<RelaysInfoGlb> known_relays):
    ioc_(ioc),
    udp_socketv4_(std::move(udp_socketv4)),
    udp_socketv6_(std::move(udp_socketv6)),
    running_(false),
    known_relays_(std::move(known_relays)),
    default_ci_(nullptr),
    raw_packet_pool_(Settings::ARENA_SLOTS, "client_logger"),
    utun_stream_(ioc_),
    utun_("client_logger"){
    logger_ = quill::Frontend::get_logger("client_logger");
    default_vpn_v4_ = RandomGen::gen_address_v4();
    default_vpn_v6_ = RandomGen::gen_address_v6();
}


Client::~Client(){
    if(running_.load()){
        stop();
    }
}


[[nodiscard]] asio::awaitable<bool> Client::start(bool hijack_system_traffic, bool act_dead){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "Called start() more than once.");
        co_return false;
    }

    if(act_dead){
        LOG_INFO(logger_, "Started 'dead' client");
        co_return true;
    }

    if(hijack_system_traffic){
        std::lock_guard<std::mutex> lock(known_relays_->registry_mutex_);
        const asio::ip::address prefix_v4 = asio::ip::make_address("255.255.255.255");
        for(auto& rinfo: known_relays_->usable_relays){
            if(!utun_.add_del_route(true, rinfo.endpoint.address(), prefix_v4)){
                LOG_ERROR(logger_, "Failed to add {} to utun routes.", rinfo.endpoint.address().to_string());
                co_return false;
            }
            LOG_INFO(logger_, "Added {} to utun routes.", rinfo.endpoint.address().to_string());
        }
    }

    if(!co_await make_new_circuit(std::nullopt)){
        LOG_ERROR(logger_, "Failed to make default circuit.");
        co_return false;
    }

    if(!utun_.start(hijack_system_traffic, default_vpn_v4_, default_vpn_v6_)){
        LOG_ERROR(logger_, "Failed to start utun.");
        co_return false;
    }
    LOG_INFO(logger_, "[UTUN] Started successfully.");

    if(!hijack_system_traffic){
        simulate_system_traffic();
    }

    utun_sockfd_ = utun_.get_fd();

    boost::system::error_code ec;
    if(utun_stream_.assign(utun_sockfd_, ec)){
        LOG_ERROR(logger_, "Failed to convert utun_sockfd_ to asio stream_descriptor.");
        co_return false;
    }

    start_listening_utun();

    LOG_INFO(logger_, "Started successfully.");
    co_return true;
}


inline void Client::start_listening_utun(){
    ArenaSlot<utun::RawPacket> raw_packet = raw_packet_pool_.alloc();
    read_packet_utun(std::move(raw_packet));
}


void Client::read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet){
    // todo: check if this reads whole packet. if it doesn't, how do we make it read the whole packet?
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

    NetworkTuple nt = NetworkTuple::create_client_nt(
        raw_packet->src_addr,
        raw_packet->dest_addr,
        raw_packet->src_port,
        raw_packet->dest_port
    );

    auto ci = nt_ci_umap_.get(nt);
    if(ci == nullptr) [[unlikely]] {
        ci = track_new_nt(nt, raw_packet);
        if(ci == nullptr)
            return;
    }

    // update seq_id before returning to read_packet.
    const sequence_id_t seq_id = (*ci->sequence_id_ptr)++;

    // continue_process_raw_packet(std::move(raw_packet), ci);
    asio::post(ioc_, [me = shared_from_this(), rp = std::move(raw_packet), ci, seq_id]() mutable{
        me->continue_process_raw_packet(std::move(rp), ci, seq_id);
        ci->touch(me);
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
            .payload_tier = PayloadTier::TIER_1024,
            ._reserved_   = {}
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
std::shared_ptr<CircuitInfo> Client::track_new_nt(NetworkTuple& nt, ArenaSlot<utun::RawPacket>& raw_packet){
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
        me->compute_new_nt_ci(ps);
    });
    return nullptr;
}


void Client::compute_new_nt_ci(std::shared_ptr<OngoingCircuitCalcInfo> cci){
    // default circuit, udpate once it proves it's network-heavy
    auto final_ci = std::make_shared<CircuitInfo>(CircuitInfo{
        .circuit_id       = default_ci_->circuit_id,
        .sequence_id_ptr  = default_ci_->sequence_id_ptr,
        .relays           = default_ci_->relays,
        .reorder_buffer   = default_ci_->reorder_buffer,
        .nt               = cci->nt,
        .activity_counter = std::make_shared<Statistics<10>>(),
    });


    // After computing circuit:

    // 1. update OngoingCircuitCalcInfo's ci to the actual ci
    // 2. cci->is_building = false;

    // steps 1 and 2 prevent this problem:
    //      * non-pioneer (in handle_non_pioneers()) pushing into the queue just as drain_new_circuit_packets() finishes.

    // 3. drain waiting packets         -> updates nt_ci_umap_
    // 4. erase from ci_computing_

    cci->ci = final_ci;
    cci->is_building.store(false, std::memory_order_release);
    drain_new_nt_packets(cci);
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
        drain_new_nt_packets(curr_state);
    }
}


void Client::drain_new_nt_packets(const std::shared_ptr<OngoingCircuitCalcInfo>& state){
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
    // todo: this properly
    if(!ci || ci->relays.empty()){
        return nullptr;
    }
    const size_t idx = relay_rr_counter_.fetch_add(1, std::memory_order_relaxed) % ci->relays.size();
    return ci->relays[idx];
}


void Client::stop(){
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "Called stop() more than once.");
        return;
    }

    utun_.stop();

    // TODO: signal relays/exit
}


asio::awaitable<bool> Client::make_new_circuit(std::optional<NetworkTuple> nt){
    if(nt.has_value()){
        LOG_INFO(logger_, "Starting making new circuit, requested by: {}", nt.value().to_string());
        if(nt->c_dest_addr().is_v6()){
            LOG_INFO(logger_, "Requested destination ip is ipv6, can't make new circuit. aborting.");
            co_return false;
        }
    }
    else{
        if(default_ci_ != nullptr){
            LOG_ERROR(logger_, "Requested to make default circuit more than once.");
            co_return false;
        }
        LOG_INFO(logger_, "Starting making default circuit.");
    }

    LOG_INFO(logger_, "All known relays size: {}", known_relays_->all_relays.size());
    LOG_INFO(logger_, "Usable relays size: {}", known_relays_->usable_relays.size());

    {
        std::lock_guard<std::mutex> lock(known_relays_->registry_mutex_);
        LOG_DEBUG(logger_, "all relays:");
        for(const auto& rinfo: known_relays_->all_relays){
            LOG_DEBUG(logger_, "\t {}:{}", rinfo.endpoint.address().to_string(), rinfo.endpoint.port());
        }
        LOG_DEBUG(logger_, "usable relays:");
        for(const auto& rinfo: known_relays_->usable_relays){
            LOG_DEBUG(logger_, "\t {}:{}", rinfo.endpoint.address().to_string(), rinfo.endpoint.port());
        }
    }

    std::vector<std::shared_ptr<RelayInfo>> relay_list;
    if(known_relays_){
        std::lock_guard<std::mutex> lock(known_relays_->registry_mutex_);
        for(const auto& rinfo: known_relays_->usable_relays){
            relay_list.push_back(std::make_shared<RelayInfo>(rinfo));
        }
    }

    if(relay_list.size() < Settings::DEFAULT_NUM_ENTRY_RELAYS){
        LOG_INFO(logger_, "Couldn't make new circuit, not enough relays. Tried choosing: {}", relay_list.size());
        co_return false;
    }

    circuit_id_t assigned_cid = RandomGen::gen_circuit_id();

    // todo: proper exit choosing
    asio::ip::udp::endpoint exit_ep(asio::ip::make_address("8.8.8.8"), 7000);

    // RELAY_SETUP_EXIT_REQ (tell relays about the new exit)
    std::vector<std::shared_ptr<RelayInfo>> selected_relays;
    size_t added_relays = 0;
    for(auto& rinfo: relay_list){
        if(rinfo->is_connected()){
            auto txn_id = RandomGen::gen_txn_id();
            auto setup_packet = make_relay_setup_exit_req_packet(rinfo->session_id, exit_ep, txn_id, assigned_cid);
            auto sock = (rinfo->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

            LOG_INFO(logger_, "Trying to setup exit info with relay : {}", rinfo->to_string());

            auto res = co_await Node::control_send_and_wait_udp(sock, setup_packet, rinfo->endpoint, txn_id, known_relays_, logger_);

            if(std::holds_alternative<std::vector<uint8_t>>(res)){
                auto response_vec = std::get<std::vector<uint8_t>>(std::move(res));
                // process_incoming_packet already parsed packet
                if(response_vec.size() < sizeof(RelaySetupExitRes)){
                    LOG_INFO(logger_, "Couldn't setup relay for exit : received response size too small.");
                    continue;
                }

                RelaySetupExitRes response{};
                std::memcpy(&response, response_vec.data(), sizeof(response));
                if(response.status){
                    LOG_INFO(logger_, "Couldn't setup relay for exit : status : {}", response.status);
                    continue;
                }

                LOG_INFO(logger_, "Setup relay for exit.");
                added_relays++;
                selected_relays.push_back(rinfo);
            }
            else{
                LOG_ERROR(logger_, "Couldn't setup relay for exit : {}", std::get<Node::CommError>(res).what());
                continue;
            }
        }

        if(added_relays >= Settings::DEFAULT_NUM_ENTRY_RELAYS)
            break;
    }
    if(added_relays < Settings::DEFAULT_NUM_ENTRY_RELAYS){
        LOG_INFO(logger_, "Couldn't make new circuit, num of relays accepted : {} out of required {}",
                 added_relays,
                 Settings::DEFAULT_NUM_ENTRY_RELAYS
        );
        co_return false;
    }
    LOG_INFO(logger_, "{} relays ready to connect to exit.", added_relays);


    // full circuit creation with exit through one relay
    sequence_id_t our_start_seq = RandomGen::gen_seq_id();
    sequence_id_t exit_start_seq = 0;
    auto txn_id = RandomGen::gen_txn_id();
    auto primary_relay = selected_relays[0];

    std::vector<uint8_t> create_packet;
    if(nt.has_value()){
        // not default circuit
        create_packet = make_exit_handshake_packet(primary_relay->session_id, assigned_cid, txn_id, our_start_seq, selected_relays,
                                                   default_vpn_v4_, nt->c_src_port(), nt->c_dest_addr().to_v4(), nt->c_dest_port(), false);
    }
    else{
        // default circuit
        create_packet = make_exit_handshake_packet(primary_relay->session_id, assigned_cid, txn_id, our_start_seq, selected_relays,
                                                   default_vpn_v4_, 0, asio::ip::address_v4(), 0, true);
    }

    auto sock = (primary_relay->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

    auto res = co_await Node::control_send_and_wait_udp(sock, create_packet, primary_relay->endpoint, txn_id, known_relays_, logger_);

    if(std::holds_alternative<std::vector<uint8_t>>(res)){
        auto response_vec = std::get<std::vector<uint8_t>>(std::move(res));
        // process_incoming_packet already parsed packet
        if(response_vec.size() < sizeof(RelaySetupExitRes)){
            LOG_INFO(logger_, "Couldn't connect to exit : received response size too small.");
            co_return false;
        }

        ExitHandshakeRes response{};
        std::memcpy(&response, response_vec.data(), sizeof(ExitHandshakeRes));

        if(response.status_code){
            LOG_INFO(logger_, "Couldn't connect to exit : status : {}", response.status_code);
            co_return false;
        }

        if(response.confirmed_cid != assigned_cid){
            LOG_INFO(logger_, "Couldn't connect to exit : received unexpected confirmed_cid.");
            co_return false;
        }

        exit_start_seq = response.start_seq_exit;
        LOG_INFO(logger_, "Setup relay for exit.");
    }
    else{
        LOG_ERROR(logger_, "Couldn't connect to exit : {}", std::get<Node::CommError>(res).what());
        co_return false;
    }

    auto final_ci = std::make_shared<CircuitInfo>(CircuitInfo{
        .circuit_id       = assigned_cid,
        .sequence_id_ptr  = std::make_shared<std::atomic<sequence_id_t>>(exit_start_seq),
        .relays           = selected_relays,
        .reorder_buffer   = std::make_shared<ReorderBuffer<ArenaSlot<IncomingCell>, sequence_id_t>>(ioc_, 2048, exit_start_seq),
        .nt               = nt,
        .activity_counter = std::make_shared<Statistics<10>>()
    });

    for(const auto& rinfo: selected_relays){
        sid_ci_umap_.put(rinfo->session_id, final_ci);
    }

    // update nt_ci_umap_. new packets should use the new ci from now
    // for packets which are being processed (using the old one), the continue to use the old one
    // NOTE: if a packet using new circuit goes in faster than ones with the old circuit, god (or the app) handles it
    if(nt.has_value()){
        nt_ci_umap_.put(nt.value(), final_ci);
        LOG_INFO(logger_, "New circuit successfully setup.");
    }
    else{
        default_ci_ = final_ci;
        LOG_INFO(logger_, "Default circuit successfully setup.");
    }
    co_return true;
}


void Client::process_incoming_packet(ArenaSlot<IncomingCell> packet){
    if(!packet){
        LOG_WARNING(logger_, "Recieved empty packet.");
        return;
    }

    if(!parse_incoming_packet(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet, couldn't parse packet");
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
    constexpr size_t min_hdr_sz = sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ;
    if(packet->bytes_received < min_hdr_sz){
        return false;
    }

    uint32_t net_sid = 0;
    std::memcpy(&net_sid, packet->payload.data() + sizeof(RoutingFlag), sizeof(net_sid));
    packet->sid = ntohl(net_sid);

    // todo: decrypt_using_sh_cr()

    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + sizeof(RoutingFlag) + sizeof(session_id_t), TRANSIT_HDR_SZ);
    packet->cid = thdr.circuit_id;

    if(packet->cid == static_cast<circuit_id_t>(-1) || thdr.flags == static_cast<uint16_t>(ThdrFlag::CONTROL)){
        packet->start_offset = min_hdr_sz;
        packet->payload_bytes = packet->bytes_received - min_hdr_sz;
        return true;
    }

    // todo: decrypt_using_sh_ce()

    constexpr size_t min_data_sz = sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ;
    if(packet->bytes_received < min_data_sz){
        return false;
    }

    PayloadHeader phdr{};
    std::memcpy(&phdr, packet->payload.data() + min_hdr_sz, PAYLOAD_HDR_SZ);
    packet->seq_id = phdr.sequence_id;

    packet->start_offset = min_data_sz;
    const size_t available_payload = packet->bytes_received - min_data_sz;
    packet->payload_bytes = std::min(static_cast<size_t>(phdr.payload_len), available_payload);

    if(packet->payload_bytes > 0){
        const uint8_t ip_ver = (packet->payload[packet->start_offset] >> 4) & 0x0F;
        packet->ip_version_macos = (ip_ver == 6) ? htonl(AF_INET6) : htonl(AF_INET);
    }
    else{
        packet->ip_version_macos = htonl(AF_INET);
    }

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

    if(known_relays_){
        Node::resume_control_operation(chdr.txn_id, std::move(payload_data), known_relays_);
    }
}


void Client::insert_into_rob(ArenaSlot<IncomingCell> packet){
    auto circuit_info = sid_ci_umap_.get(packet->sid);
    circuit_info->touch(shared_from_this());
    if(!circuit_info){
        LOG_WARNING(logger_, "Recieved incoming packet with unknown sid: {}, cid: {}", packet->sid, packet->cid);
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
        LOG_ERROR(logger_, "Reorder buffer insert failed for seq_id {}", packet->seq_id);
    }
}


void Client::write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet){
    if(!packet || packet->payload_bytes == 0){
        return;
    }

    std::unique_lock<std::mutex> lock(utun_write_mtx_);
    utun_write_queue_.push_back(std::move(packet));
    if(!utun_writing_){
        utun_writing_ = true;
        do_write_utun(std::move(lock), seq_id);
    }
}


void Client::do_write_utun(std::unique_lock<std::mutex> lock, sequence_id_t seq_id){
    if(utun_write_queue_.empty()){
        utun_writing_ = false;
        return;
    }

    auto& pkt = utun_write_queue_.front();

    // scatter gather buffer. for macOS, we need to include ip version (4 bytes)
#if defined(__APPLE__)
    std::array<asio::const_buffer, 2> bufs = {
        asio::buffer(&pkt->ip_version_macos, FAMILY_HDR_UTUN_SZ),
        asio::buffer(pkt->payload.data() + pkt->start_offset, pkt->payload_bytes)
    };
#elif defined(__linux__)
    std::array<asio::const_buffer, 1> bufs = {
        asio::buffer(pkt->payload.data() + pkt->start_offset, pkt->payload_bytes)
    };
#else
    // not compatible
#endif

    lock.unlock();

    asio::async_write(
        utun_stream_,
        bufs,
        [me = shared_from_this(), seq_id](const boost::system::error_code& ec, size_t /*bytes_transferred*/){
            if(ec){
                LOG_ERROR(me->logger_, "Failed to write to utun: {}, seq_id: {}", ec.message(), seq_id);
            }
            std::unique_lock<std::mutex> lk(me->utun_write_mtx_);
            if(!me->utun_write_queue_.empty()){
                me->utun_write_queue_.pop_front();
            }
            me->do_write_utun(std::move(lk), seq_id + 1);
        }
    );
}


std::vector<uint8_t> Client::make_relay_setup_exit_req_packet(const session_id_t sid,
                                                              const asio::ip::udp::endpoint& exit_ep,
                                                              txn_id_t txn_id,
                                                              circuit_id_t circuit_id){
    std::vector<uint8_t> buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelaySetupExitReq));
    size_t offset = 0;

    buf[offset] = static_cast<uint8_t>(RoutingFlag::CLIENT_TO_RELAY);
    offset += sizeof(RoutingFlag);

    for(size_t i = 0; i < sizeof(session_id_t); i++){
        buf[offset + i] = static_cast<uint8_t>((sid >> (8 * (sizeof(session_id_t) - 1 - i))) & 0xFF);
    }
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelaySetupExitReq));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader chdr{};
    chdr.msg_type = ControlMsgType::RELAY_SETUP_EXIT_REQ;
    chdr.flags = 0;
    chdr.payload_len = static_cast<uint16_t>(sizeof(RelaySetupExitReq));
    chdr.txn_id = txn_id;
    std::memcpy(buf.data() + offset, &chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    RelaySetupExitReq req{};
    req.circuit_id = circuit_id;
    req.exit_ipv4 = htonl(exit_ep.address().to_v4().to_uint());
    req.exit_port = htons(exit_ep.port());
    std::memcpy(buf.data() + offset, &req, sizeof(RelaySetupExitReq));

    return buf;
}


std::vector<uint8_t> Client::make_exit_handshake_packet(const session_id_t sid,
                                                        const circuit_id_t cid,
                                                        txn_id_t txn_id,
                                                        sequence_id_t our_start_seq,
                                                        const std::vector<std::shared_ptr<RelayInfo>>& selected_relays,
                                                        const asio::ip::address_v4& our_address_v4,
                                                        const uint16_t our_port,
                                                        const asio::ip::address_v4& dest_address_v4,
                                                        const uint16_t dest_port,
                                                        bool default_circuit){
    std::vector<uint8_t> buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(ExitHandshakeReq));
    size_t offset = 0;

    buf[offset] = static_cast<uint8_t>(RoutingFlag::CLIENT_TO_RELAY);
    offset += sizeof(RoutingFlag);

    for(size_t i = 0; i < sizeof(session_id_t); i++){
        buf[offset + i] = static_cast<uint8_t>((sid >> (8 * (sizeof(session_id_t) - 1 - i))) & 0xFF);
    }
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = cid;
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(ExitHandshakeReq));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader chdr{};
    chdr.msg_type = ControlMsgType::EXIT_HANDSHAKE_REQ;
    chdr.flags = 0;
    chdr.payload_len = static_cast<uint16_t>(sizeof(ExitHandshakeReq));
    chdr.txn_id = txn_id;
    std::memcpy(buf.data() + offset, &chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    RelayList relay_list{};
    uint16_t populated = 0;
    for(const auto& rinfo: selected_relays){
        if(populated >= MAX_RELAYS_PER_CIRCUIT)
            break;
        if(rinfo->endpoint.address().is_v4()){
            relay_list.relays[populated].ipv4 = htonl(rinfo->endpoint.address().to_v4().to_uint());
            relay_list.relays[populated].port = htons(rinfo->endpoint.port());
            relay_list.relays[populated].nat = 0;
            relay_list.relays[populated].bandwidth_tier = 0;
            populated++;
        }
    }
    relay_list.count = populated;

    ExitHandshakeReq req{};
    req.requested_cid = cid;
    req.start_seq_client = our_start_seq;
    req.relay_list = relay_list;
    req.client_ipv4 = htonl(our_address_v4.to_uint());
    req.client_port = our_port;
    req.dest_ipv4 = htonl(dest_address_v4.to_uint());
    req.dest_port = dest_port;
    req.default_circuit = default_circuit;
    std::memcpy(buf.data() + offset, &req, sizeof(ExitHandshakeReq));

    return buf;
}


namespace{
#include <array>
#include <chrono>
#include <memory>
#include <netinet/ip_icmp.h>

#if defined(__APPLE__)
// fallback of icmphdr (not available in macos)
struct icmphdr{
    uint8_t type;      // ICMP message type
    uint8_t code;      // ICMP operation code
    uint16_t checksum; // ICMP checksum
    union{
        struct{
            uint16_t id;
            uint16_t sequence;
        } echo;           // Echo datagram
        uint32_t gateway; // Gateway address
        struct{
            uint16_t unused;
            uint16_t mtu;
        } frag; // Path MTU discovery
    } un;
};
#endif


uint16_t calculate_checksum(const uint16_t* data, size_t length){
    uint32_t sum = 0;
    while(length > 1){
        sum += *data++;
        length -= 2;
    }
    if(length == 1){
        sum += *reinterpret_cast<const uint8_t*>(data);
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}


std::vector<uint8_t> build_icmp_echo_packet(const asio::ip::address_v4& src_ip,
                                            const asio::ip::address_v4& dst_ip,
                                            uint16_t seq_num){
    std::vector<uint8_t> packet;

    size_t header_offset = 0;
#if defined(__APPLE__)
    // macOS utun requires a 4-byte address family header (AF_INET in network byte order)
    uint32_t family_hdr = htonl(AF_INET);
    packet.resize(FAMILY_HDR_UTUN_SZ);
    std::memcpy(packet.data(), &family_hdr, FAMILY_HDR_UTUN_SZ);
    header_offset = FAMILY_HDR_UTUN_SZ;
#endif

    const size_t ip_len = sizeof(struct ip);
    const size_t icmp_len = sizeof(struct icmphdr);
    const std::string payload = "PING_SIMULATION";
    const size_t total_ip_packet_len = ip_len + icmp_len + payload.size();

    packet.resize(header_offset + total_ip_packet_len, 0);
    uint8_t* ip_buf = packet.data() + header_offset;

    // 1. Fill IPv4 Header
    auto* iph = reinterpret_cast<struct ip*>(ip_buf);
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons(static_cast<uint16_t>(total_ip_packet_len));
    iph->ip_id = htons(seq_num);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_ICMP;
    iph->ip_src.s_addr = inet_addr(src_ip.to_string().c_str());
    iph->ip_dst.s_addr = inet_addr(dst_ip.to_string().c_str());
    iph->ip_sum = 0;
    iph->ip_sum = calculate_checksum(reinterpret_cast<const uint16_t*>(iph), ip_len);

    // 2. Fill ICMP Echo Request Header + Payload
    uint8_t* icmp_buf = ip_buf + ip_len;
    auto* icmph = reinterpret_cast<struct icmphdr*>(icmp_buf);
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(0x1234);
    icmph->un.echo.sequence = htons(seq_num);
    icmph->checksum = 0;

    std::memcpy(icmp_buf + icmp_len, payload.data(), payload.size());
    icmph->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(icmp_buf), icmp_len + payload.size());

    return packet;
}
}


void Client::simulate_system_traffic(){
    auto timer = std::make_shared<asio::steady_timer>(ioc_);
    auto seq_num = std::make_shared<uint16_t>(0);

    const auto target_ip = asio::ip::make_address_v4("1.1.1.1");

    auto schedule_next = std::make_shared<std::function<void()>>();
    *schedule_next = [this, timer, seq_num, target_ip, schedule_next](){
        timer->expires_after(std::chrono::seconds(2));
        timer->async_wait([this, timer, seq_num, target_ip, schedule_next](const boost::system::error_code& ec){
            if(ec){
                return;
            }

            (*seq_num)++;
            auto raw_packet = std::make_shared<std::vector<uint8_t>>(
                build_icmp_echo_packet(default_vpn_v4_, target_ip, *seq_num)
            );

            asio::async_write(
                utun_stream_,
                asio::buffer(*raw_packet),
                [this, raw_packet, timer, schedule_next](const boost::system::error_code& write_ec, std::size_t /*bytes_transferred*/){
                    if(write_ec){
                        LOG_ERROR(logger_, "[UTUN] Failed to write simulated traffic packet: {}", write_ec.message());
                        return;
                    }
                    (*schedule_next)();
                }
            );
        });
    };

    (*schedule_next)();
}
