#include <src/node/roles/exit.hpp>
#include "src/encryption/encryption.hpp"

#include <quill/LogMacros.h>


Exit::Exit(asio::io_context& ioc,
           std::shared_ptr<asio::ip::udp::socket> udp_socketv4,
           std::shared_ptr<asio::ip::udp::socket> udp_socketv6):
    ioc_(ioc),
    udp_socketv4_(std::move(udp_socketv4)),
    udp_socketv6_(std::move(udp_socketv6)),
    running_(false),
    raw_packet_pool_(16384, "exit_logger"),
    utun_stream_(ioc_),
    utun_("exit_logger"){
    logger_ = quill::Frontend::get_logger("exit_logger");
}


Exit::~Exit(){
    if(running_.load()){
        stop();
    }
}


[[nodiscard]] bool Exit::start(){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "Called start() more than once.");
        return false;
    }

    if(!utun_.start(false, RandomGen::gen_address_v4(), RandomGen::gen_address_v6())){
        LOG_ERROR(logger_, "[UTUN] Failed to start utun.");
        return false;
    }
    LOG_INFO(logger_, "[UTUN] Started successfully.");

    utun_sockfd_ = utun_.get_fd();

    if(boost::system::error_code ec; utun_stream_.assign(utun_sockfd_, ec)){
        LOG_ERROR(logger_, "Failed to convert utun_sockfd_ to asio stream_descriptor, ec: {}", ec.message());
        return false;
    }

    start_listening_utun();

    LOG_INFO(logger_, "Started successfully.");
    return true;
}


void Exit::stop(){}


void Exit::start_listening_utun(){
    ArenaSlot<utun::RawPacket> raw_packet = raw_packet_pool_.alloc();
    read_packet_utun(std::move(raw_packet));
}


void Exit::read_packet_utun(ArenaSlot<utun::RawPacket> raw_packet){
    // TODO: check if this reads whole packet. if it doesn't, how do we make it read the whole packet?
    utun_stream_.async_read_some(
        asio::buffer(raw_packet->payload),
        [me=shared_from_this(), rp = std::move(raw_packet)](const boost::system::error_code& ec, std::size_t bytes_xfer) mutable{
            rp->bytes_received = bytes_xfer;
            me->loop_utun(std::move(rp), ec);
        }
    );
}


void Exit::loop_utun(ArenaSlot<utun::RawPacket> raw_packet, boost::system::error_code const& ec){
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


void Exit::process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet){
    if(!raw_packet->parse_packet()){
        LOG_ERROR(logger_, "Dropping faulty packet from utun, couldn't parse properly.");
        return;
    }

    // NOTE: src_addr is destination's ip, dest_addr is client's virtual ip
    NetworkTuple nt = NetworkTuple::create_exit_nt(
        raw_packet->dest_addr,
        raw_packet->src_addr,
        raw_packet->dest_port,
        raw_packet->src_port
    );

    // first check for nt, then for default circuits (sant)
    auto ci = nt_ci_umap_.get(nt);
    if(ci == nullptr){
        const SrcAddrNetworkTuple sant{
            .e_client_addr = nt.e_client_addr()
        };
        ci = sant_ci_umap_.get(sant);

        if(ci == nullptr) [[unlikely]] {
            LOG_ERROR(logger_, "Dropping faulty packet from utun, circuit information couldn't be found from parsed nt.");
            return;
        }
    }

    // update seq_id before returning to read_packet.
    const sequence_id_t seq_id = (*ci->sequence_id_ptr)++;

    // continue_process_raw_packet(std::move(raw_packet), ci);
    asio::post(ioc_, [me = shared_from_this(), rp = std::move(raw_packet), ci, seq_id]() mutable{
        me->continue_process_raw_packet(std::move(rp), ci, seq_id);
    });

    // returns to loop_utun
}


void Exit::continue_process_raw_packet(ArenaSlot<utun::RawPacket> raw_packet, std::shared_ptr<CircuitInfo> circuit_info, sequence_id_t seq_id){
    const auto relay = choose_relay(circuit_info);
    if(!relay){
        LOG_WARNING(logger_, "No relay available to send packet for cid {}", circuit_info->circuit_id);
        return;
    }

    const auto app_internal_bytes = raw_packet->bytes_received - FAMILY_HDR_UTUN_SZ;
    constexpr size_t HEADER_SZ = sizeof(RoutingFlag) + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ;
    auto header_buf = std::make_shared<std::array<uint8_t, HEADER_SZ>>();
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::EXIT_TO_RELAY);
    std::memcpy(header_buf->data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    TransitHeader thdr{
        .circuit_id   = circuit_info->circuit_id,
        .frame_len    = static_cast<uint16_t>(PAYLOAD_HDR_SZ + app_internal_bytes),
        .flags        = 0,
        .payload_tier = PayloadTier::TIER_1024,
        ._reserved_   = {0, 0, 0}
    };
    std::memcpy(header_buf->data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    PayloadHeader phdr{
        .sequence_id = seq_id,
        .ip_protocol = 0,
        .packet_id   = 0,
        .payload_len = static_cast<uint16_t>(app_internal_bytes),
        .frag_index  = 0,
        .frag_total  = 0
    };
    std::memcpy(header_buf->data() + offset, &phdr, PAYLOAD_HDR_SZ);

    // encrypt using sh_ce: phdr + ip payload
    crypto::encrypt_layer_ce(circuit_info->sh_ce, header_buf->data() + sizeof(RoutingFlag) + TRANSIT_HDR_SZ, PAYLOAD_HDR_SZ);
    crypto::encrypt_layer_ce(circuit_info->sh_ce, raw_packet->payload.data() + FAMILY_HDR_UTUN_SZ, app_internal_bytes);

    size_t outgoing_bytes = HEADER_SZ + app_internal_bytes;
    const std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(*header_buf),
        asio::buffer(raw_packet->payload.data() + FAMILY_HDR_UTUN_SZ, app_internal_bytes)
    };

    std::shared_ptr<asio::ip::udp::socket> sock = (relay->endpoint.protocol() == asio::ip::udp::v4())
                                                      ? udp_socketv4_
                                                      : udp_socketv6_;

    // @formatter:off
    sock->async_send_to(
        outgoing,
        relay->endpoint,
        // raw_packet and header_buf in the lambda to make sure it doesn't get destroyed
        // NOTE: compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), outgoing_bytes, keep_alive1 = std::move(raw_packet), keep_alive2 = header_buf]
        (const boost::system::error_code& ec, std::size_t bytes_xfer){
            if(ec){
                LOG_ERROR(me->logger_, "Send failed: {}", ec.message());
                return;
            }
            if(bytes_xfer != outgoing_bytes){
                LOG_ERROR(me->logger_, "Bytes sent mismatch: UDP socket fail?");
                return;
            }
        }
    );
    // @formatter:on
}


std::shared_ptr<RelayInfo> Exit::choose_relay(const std::shared_ptr<CircuitInfo>& ci){
    // todo: this better
    if(!ci || ci->relays.empty()){
        return nullptr;
    }
    const size_t idx = relay_rr_counter_.fetch_add(1, std::memory_order_relaxed) % ci->relays.size();
    return ci->relays[idx];
}


void Exit::process_incoming_packet(ArenaSlot<IncomingCell> packet, asio::ip::udp::endpoint sender_endpoint){
    if(!packet){
        LOG_WARNING(logger_, "Recieved empty packet.");
        return;
    }

    if(!parse_headers_incoming_packet(packet)){
        LOG_ERROR(logger_, "Failed to parse incoming packet.");
        return;
    }

    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + sizeof(RoutingFlag), TRANSIT_HDR_SZ);
    if(thdr.flags == static_cast<uint16_t>(ThdrFlag::CONTROL)) [[unlikely]] {
        handle_control_from_relay(std::move(packet), sender_endpoint);
        return;
    }

    insert_into_rob(std::move(packet));
}


void Exit::handle_control_from_relay(ArenaSlot<IncomingCell> packet, const asio::ip::udp::endpoint& relay_endpoint){
    const size_t min_sz = sizeof(RoutingFlag) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ;
    if(packet->bytes_received < min_sz){
        LOG_ERROR(logger_, "Dropping control packet at exit: size too small ({})", packet->bytes_received);
        return;
    }

    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + sizeof(RoutingFlag), TRANSIT_HDR_SZ);

    ControlHeader chdr{};
    std::memcpy(&chdr, packet->payload.data() + sizeof(RoutingFlag) + TRANSIT_HDR_SZ, CONTROL_HDR_SZ);

    const uint8_t* body_ptr = packet->payload.data() + sizeof(RoutingFlag) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ;
    const size_t body_len = packet->bytes_received - min_sz;

    switch(chdr.msg_type){
        case ControlMsgType::EXIT_HANDSHAKE_REQ: {
            if(body_len < sizeof(ExitHandshakeReq)){
                LOG_ERROR(logger_, "ExitCircuitCreateReq payload too small.");
                return;
            }
            ExitHandshakeReq req{};
            std::memcpy(&req, body_ptr, sizeof(ExitHandshakeReq));

            const circuit_id_t cid = req.requested_cid;
            const sequence_id_t client_initial_seq = req.start_seq_client;
            const sequence_id_t our_initial_seq = RandomGen::gen_seq_id();

            std::shared_ptr<CircuitInfo> ci = nullptr;

            LOG_INFO(logger_, "Handshake request received for cid: {}, relay_endpoint: {}:{}", cid,
                     relay_endpoint.address().to_string(), relay_endpoint.port());

            crypto::EphemeralDH dh;
            crypto::Key256 sh_ce{};
            crypto::PubKey256 peer_pubkey{};
            std::memcpy(peer_pubkey.data(), req.public_key, sizeof(peer_pubkey));
            if(!dh.compute_shared_secret(peer_pubkey, sh_ce)){
                LOG_ERROR(logger_, "Exit failed to compute shared secret SH_CE with client for cid: {}", cid);
                return;
            }

            // insert cid in cid_ci_umap_
            {
                std::vector<std::shared_ptr<RelayInfo>> relays;
                for(size_t i = 0; i < req.relay_list.count; i++){
                    const auto& relay = req.relay_list.relays[i];
                    if(relay.ipv4 == 0)
                        continue;
                    RelayInfo rinfo;
                    rinfo.session_id = static_cast<session_id_t>(-1);
                    rinfo.endpoint = asio::ip::udp::endpoint(asio::ip::address_v4(relay.ipv4), relay.port);
                    relays.push_back(std::make_shared<RelayInfo>(rinfo));
                }

                ci = std::make_shared<CircuitInfo>(CircuitInfo{
                    .circuit_id       = cid,
                    .sequence_id_ptr  = std::make_shared<std::atomic<sequence_id_t>>(our_initial_seq),
                    .relays           = std::move(relays),
                    .sh_ce            = sh_ce,
                    .reorder_buffer   = std::make_shared<ReorderBuffer<ArenaSlot<IncomingCell>, sequence_id_t>>(ioc_, Settings::REORDER_BUFFER_SIZE, client_initial_seq, logger_),
                    /* not used by exit, compiler warns */
                    .nt               = NetworkTuple::create_exit_nt(asio::ip::address{}, asio::ip::address{}, 0, 0),
                    .activity_counter = {}
                });

                cid_ci_umap_.put(cid, ci);
            }

            // update sant_nt_ci_umap_/nt_ci_umap_ (assign virtual ip to client, use that for nt_ci)
            {
                asio::ip::address_v4 client_req_private_ip = asio::ip::make_address_v4(req.client_ipv4);

                if(req.default_circuit){
                    SrcAddrNetworkTuple nt{
                        .e_client_addr = client_req_private_ip
                    };
                    sant_ci_umap_.put_if_absent(nt, ci);
                }
                else{
                    asio::ip::address_v4 destinatation_ip = asio::ip::make_address_v4(req.dest_ipv4);
                    uint16_t client_port = req.client_port;
                    uint16_t dest_port = req.dest_port;

                    NetworkTuple nt = NetworkTuple::create_exit_nt(
                        client_req_private_ip,
                        destinatation_ip,
                        client_port,
                        dest_port
                    );
                    nt_ci_umap_.put_if_absent(nt, ci);
                }
            }

            // build EXIt to send back through the relay
            // RoutingFlag::EXIT_TO_RELAY + TransitHeader + ControlHeader + ExitCircuitCreateRes
            auto resp_packet = make_exit_handshake_resp_packet(chdr, cid, our_initial_seq, Settings::REORDER_BUFFER_SIZE, dh.public_key());

            auto sock = (relay_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_packet));
            sock->async_send_to(
                asio::buffer(*send_data),
                relay_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t){
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send ExitCircuitCreateRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        default:
            LOG_WARNING(logger_, "Unhandled control message: {}", static_cast<int>(chdr.msg_type));
            break;
    }
}


std::vector<uint8_t> Exit::make_exit_handshake_resp_packet(const ControlHeader& chdr,
                                                           circuit_id_t cid,
                                                           sequence_id_t seq_id,
                                                           uint64_t reorder_buffer_size,
                                                           const std::array<uint8_t, 32>& pubkey){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(ExitHandshakeRes));
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::EXIT_TO_RELAY);
    std::memcpy(resp_buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    TransitHeader resp_thdr{};
    resp_thdr.circuit_id = cid;
    resp_thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(ExitHandshakeRes));
    resp_thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    resp_thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(resp_buf.data() + offset, &resp_thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader resp_chdr{};
    resp_chdr.msg_type = ControlMsgType::EXIT_HANDSHAKE_RESP;
    resp_chdr.flags = 0;
    resp_chdr.payload_len = static_cast<uint16_t>(sizeof(ExitHandshakeRes));
    resp_chdr.txn_id = chdr.txn_id;
    std::memcpy(resp_buf.data() + offset, &resp_chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    ExitHandshakeRes res{
        .confirmed_cid   = cid,
        .start_seq_exit  = seq_id,
        .rob_window_size = static_cast<uint32_t>(reorder_buffer_size),
        .status_code     = 0,
        ._reserved_      = {0, 0, 0},
        .public_key      = {}
    };
    std::memcpy(res.public_key, pubkey.data(), sizeof(res.public_key));
    std::memcpy(resp_buf.data() + offset, &res, sizeof(ExitHandshakeRes));

    return resp_buf;
}


/*
incoming packet:
    route_flag
    {thdr, phdr, payload}

thdr:
circuit_id is at the start
*/
[[nodiscard]] bool Exit::parse_headers_incoming_packet(const ArenaSlot<IncomingCell>& packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + TRANSIT_HDR_SZ){
        return false;
    }

    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + sizeof(RoutingFlag), TRANSIT_HDR_SZ);

    packet->cid = thdr.circuit_id;

    if(thdr.flags == static_cast<uint16_t>(ThdrFlag::CONTROL)){
        packet->start_offset = sizeof(RoutingFlag) + TRANSIT_HDR_SZ;
        packet->payload_bytes = packet->bytes_received - packet->start_offset;
        return true;
    }

    // decrypt using sh_ce
    auto circuit_info = cid_ci_umap_.get(packet->cid);
    if(circuit_info){
        size_t inner_len = packet->bytes_received - (sizeof(RoutingFlag) + TRANSIT_HDR_SZ);
        crypto::decrypt_layer_ce(circuit_info->sh_ce, packet->payload.data() + sizeof(RoutingFlag) + TRANSIT_HDR_SZ, inner_len);
    }

    constexpr size_t min_data_sz = sizeof(RoutingFlag) + TRANSIT_HDR_SZ + PAYLOAD_HDR_SZ;
    if(packet->bytes_received < min_data_sz){
        return false;
    }

    PayloadHeader phdr{};
    std::memcpy(&phdr, packet->payload.data() + sizeof(RoutingFlag) + TRANSIT_HDR_SZ, PAYLOAD_HDR_SZ);
    packet->seq_id = phdr.sequence_id;

    packet->start_offset = min_data_sz;
    const size_t available_payload = packet->bytes_received - min_data_sz;
    packet->payload_bytes = std::min(static_cast<size_t>(phdr.payload_len), available_payload);

    if(packet->payload_bytes > 0){
        const uint8_t ip_ver = (packet->payload[packet->start_offset] >> 4) & 0x0F;
        packet->ip_version_macos = (ip_ver == 6) ? AF_INET6 : AF_INET;
    }
    else{
        packet->ip_version_macos = AF_INET;
    }

    return true;
}


void Exit::insert_into_rob(ArenaSlot<IncomingCell> packet){
    auto circuit_info = cid_ci_umap_.get(packet->cid);

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


void Exit::write_to_utun(sequence_id_t seq_id, ArenaSlot<IncomingCell> packet){
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


void Exit::do_write_utun(std::unique_lock<std::mutex> lock, sequence_id_t seq_id){
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
