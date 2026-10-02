#include <src/node/roles/exit.hpp>

#include <quill/LogMacros.h>


Exit::Exit(asio::io_context& ioc, asio::ip::udp::socket& udp_socketv4, asio::ip::udp::socket& udp_socketv6):
    ioc_(ioc),
    udp_socketv4_(udp_socketv4),
    udp_socketv6_(udp_socketv6),
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

    if(!utun_.start(false)){
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

    // fixme: src_addr is destination's ip, dest_addr is client's virtual ip
    // todo:    this ^
    // bug:     this ^^
    // NOTE:    this ^^^
    NetworkTuple nt{
        .src_addr  = raw_packet->src_addr,
        .dest_addr = raw_packet->dest_addr,

        .src_port  = raw_packet->src_port,
        .dest_port = raw_packet->dest_port,
    };

    auto ci = nt_ci_umap_.get(nt);
    if(ci == nullptr) [[unlikely]] {
        LOG_ERROR(logger_, "Dropping faulty packet from utun, circuit information couldn't be found from parsed nt.");
        return;
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

    const auto app_internal_bytes = raw_packet->bytes_received - FAMILY_HDR_UTUN_SZ;
    auto headers = std::make_shared<ExitFullHeaders>(ExitFullHeaders{
        .route_flag = RoutingFlag::EXIT_TO_RELAY,
        .thdr{
            .circuit_id   = circuit_info->circuit_id,
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

    // todo: encrypt using sh_ce
    size_t outgoing_bytes = sizeof(ClientFullHeaders) + app_internal_bytes;
    const std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(headers.get(), sizeof(ClientFullHeaders)),
        asio::buffer(raw_packet->payload.data() + FAMILY_HDR_UTUN_SZ, app_internal_bytes)
    };

    asio::ip::udp::socket& sock = (relay->endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;

    // @formatter:off
    sock.async_send_to(
        outgoing,
        relay->endpoint,
        // raw_packet and headers in the lambda to make sure it doesn't get destroyed
        // NOTE: compiler shouldn't theoretically optimize this packet out of the capture list.
        // optimize: no shared_ptrs for 1. packet, 2. headers
        [me=shared_from_this(), outgoing_bytes, keep_alive1 = std::move(raw_packet), keep_alive2 = headers]
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
    // TODO: scheduling
    return ci->relays[0];
}


void Exit::process_incoming_packet(ArenaSlot<IncomingCell> packet){
    if(!packet){
        LOG_WARNING(logger_, "Recieved empty packet.");
        return;
    }

    if(!parse_incoming_packet(packet)){
        LOG_ERROR(logger_, "Failed to parse incoming packet.");
        return;
    }

    insert_into_rob(std::move(packet));
}


/*
incoming packet:
    route_flag
    {thdr, phdr, payload}

thdr:
circuit_id is at the start
*/
[[nodiscard]] bool Exit::parse_incoming_packet(ArenaSlot<IncomingCell>& packet){
    // todo: this,
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

    // todo: this properly, payload bytes etc.
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
