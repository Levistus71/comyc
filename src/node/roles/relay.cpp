#include "src/node/roles/relay.hpp"
#include "src/network/comms/control.hpp"
#include "src/encryption/encryption.hpp"

#include <quill/LogMacros.h>
#include <quill/Frontend.h>

#include <utility>


Relay::Relay(asio::io_context& ioc,
             std::shared_ptr<asio::ip::udp::socket> sockv4,
             std::shared_ptr<asio::ip::udp::socket> sockv6,
             std::shared_ptr<RelaysInfoGlb> known_relays,
             const std::shared_ptr<network_stats::StatsReporter>& stats_reporter):
    ioc_(ioc),
    udp_socketv4_(std::move(sockv4)),
    udp_socketv6_(std::move(sockv6)),
    known_relays_(std::move(known_relays)),
    stats_reporter_(stats_reporter){
    logger_ = quill::Frontend::get_logger("relay_logger");
}


Relay::~Relay() = default;


void Relay::start() const{
    LOG_INFO(logger_, "Relay starting.");
}


void Relay::stop(){
    // todo: signal clients about exit
    LOG_INFO(logger_, "Stopped.");
}


/*
incoming packet:
    route_flag
    session_id
    {thdr, phdr, payload}
outgoing packet:
    route_flag
    {thdr, phdr, payload}
*/
[[nodiscard]] static bool parse_upper_packet_from_client(const ArenaSlot<IncomingCell>& packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + sizeof(session_id_t)){
        return false;
    }

    uint32_t net_sid = 0;
    std::memcpy(&net_sid, packet->payload.data() + sizeof(RoutingFlag), sizeof(net_sid));
    packet->sid = net_sid;

    packet->outgoing_bytes = packet->bytes_received - sizeof(session_id_t);
    packet->payload_bytes = packet->bytes_received - sizeof(RoutingFlag) - sizeof(session_id_t);
    packet->start_offset = sizeof(RoutingFlag) + sizeof(session_id_t);
    packet->route_flag = RoutingFlag::RELAY_TO_EXIT;

    return true;
}


[[nodiscard]] static bool parse_cid_from_client(const ArenaSlot<IncomingCell>& packet){
    if(packet->payload_bytes < TRANSIT_HDR_SZ){
        return false;
    }
    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + packet->start_offset, TRANSIT_HDR_SZ);
    packet->cid = thdr.circuit_id;
    packet->control_packet = packet->cid == static_cast<circuit_id_t>(-1); // || thdr.flags == static_cast<uint16_t>(ThdrFlag::CONTROL);
    // ^ maybe control for exit too: only condition: cid = -1
    return true;
}


void Relay::process_packet_from_client(ArenaSlot<IncomingCell> packet, const asio::ip::udp::endpoint& sender_endpoint){
    if(!parse_upper_packet_from_client(packet)){
        LOG_ERROR(logger_, "Dropping faulty packet, route_packet, size<5.");
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    // decrypt(packet->payload + sizeof(session_id), exit_info->sh_cr)
    std::shared_ptr<ClientInfo> client_info = nullptr;
    if(packet->sid != static_cast<session_id_t>(-1)){
        client_info = sid_ci_umap_.get(packet->sid);
        if(client_info){
            crypto::decrypt_layer_cr(client_info->sh_cr, packet->payload.data() + packet->start_offset, packet->payload_bytes);
        }
    }


    if(!parse_cid_from_client(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, unable to find cid.");
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    if(packet->control_packet){
        const uint8_t* control_data = packet->payload.data() + packet->start_offset + TRANSIT_HDR_SZ;
        const size_t control_len = packet->payload_bytes - TRANSIT_HDR_SZ;
        if(client_info){
            handle_control_from_client(packet->sid, control_data, control_len, sender_endpoint, client_info->sh_cr);
        }
        else{
            std::array<uint8_t, 32> v{};
            handle_control_from_client(packet->sid, control_data, control_len, sender_endpoint, v);
        }
        return;
    }

    forward_to_exit(std::move(packet));
}


static std::vector<uint8_t> make_relay_handshake_rep_pakcet(const session_id_t sid, const ControlHeader& chdr, const crypto::PubKey256& pubkey){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayHandshakeRes));
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::RELAY_TO_CLIENT);
    std::memcpy(resp_buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    std::memcpy(resp_buf.data() + offset, &sid, sizeof(session_id_t));
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayHandshakeRes));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(resp_buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader resp_chdr{};
    resp_chdr.msg_type = ControlMsgType::RELAY_HANDSHAKE_RESP;
    resp_chdr.flags = 0;
    resp_chdr.payload_len = static_cast<uint16_t>(sizeof(RelayHandshakeRes));
    resp_chdr.txn_id = chdr.txn_id;
    std::memcpy(resp_buf.data() + offset, &resp_chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    RelayHandshakeRes res{};
    res.session_id_res = sid;
    std::memcpy(res.public_key, pubkey.data(), sizeof(res.public_key));
    std::memcpy(resp_buf.data() + offset, &res, sizeof(RelayHandshakeRes));

    return resp_buf;
}


static std::vector<uint8_t> make_relay_list_rep_packet(const session_id_t sid, const ControlHeader& chdr, const RelayListRes& res){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayListRes));
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::RELAY_TO_CLIENT);
    std::memcpy(resp_buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    std::memcpy(resp_buf.data() + offset, &sid, sizeof(session_id_t));
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayListRes));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(resp_buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader resp_chdr{};
    resp_chdr.msg_type = ControlMsgType::RELAY_DISCOVERY_RESP;
    resp_chdr.flags = 0;
    resp_chdr.payload_len = static_cast<uint16_t>(sizeof(RelayListRes));
    resp_chdr.txn_id = chdr.txn_id;
    std::memcpy(resp_buf.data() + offset, &resp_chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    std::memcpy(resp_buf.data() + offset, &res, sizeof(RelayListRes));

    return resp_buf;
}


void Relay::handle_control_from_client(const session_id_t sid, const uint8_t* data, size_t len, const asio::ip::udp::endpoint& sender_endpoint,
                                       std::array<uint8_t, 32>& sh_cr){
    if(len < CONTROL_HDR_SZ){
        LOG_WARNING(logger_, "Dropping control packet from client: length too small ({})", len);
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    LOG_INFO(logger_, "Handling control packet from client. Endpoint: {}/{}",
             sender_endpoint.address().to_string(), sender_endpoint.port());

    ControlHeader chdr{};
    std::memcpy(&chdr, data, CONTROL_HDR_SZ);

    const uint8_t* msg_body = data + CONTROL_HDR_SZ;
    const size_t body_len = len - CONTROL_HDR_SZ;

    switch(chdr.msg_type){
        case ControlMsgType::RELAY_HANDSHAKE_REQ: {
            if(body_len < sizeof(RelayHandshakeReq)){
                LOG_WARNING(logger_, "RelayHandshakeReq payload too small.");
                stats_reporter_->stats.on_malformed_packet();
                return;
            }
            RelayHandshakeReq req{};
            std::memcpy(&req, msg_body, sizeof(RelayHandshakeReq));

            auto requested_sid = req.session_id_req;

            LOG_INFO(logger_, "HANDSHAKE: {}, endpoint: {}:{}, session_id: {}",
                     requested_sid, sender_endpoint.address().to_string(), sender_endpoint.port(), requested_sid);

            crypto::EphemeralDH dh;
            crypto::Key256 sh_cr{};
            crypto::PubKey256 peer_pubkey{};
            std::memcpy(peer_pubkey.data(), req.public_key, sizeof(peer_pubkey));
            if(!dh.compute_shared_secret(peer_pubkey, sh_cr)){
                LOG_ERROR(logger_, "Relay failed to compute shared secret SH_CR with client");
                stats_reporter_->stats.on_malformed_packet();
                return;
            }

            const ClientInfo cinfo{
                .session_id = requested_sid,
                .endpoint   = sender_endpoint,
                .sh_cr      = sh_cr
            };
            // exit information is not yet confirmed.
            sid_ci_umap_.put_if_absent(requested_sid, cinfo);

            // update known_relays_
            if(known_relays_){
                auto& mut = known_relays_->registry_mutex_;
                std::lock_guard<std::mutex> lock(mut);
                auto rinfo = RelayInfo{.session_id = requested_sid, .endpoint = sender_endpoint, .sh_cr = sh_cr};
                known_relays_->all_relays.insert(rinfo);
                if(!known_relays_->usable_relays.contains(rinfo) && is_relay_diverse(rinfo.endpoint, known_relays_->usable_relays, udp_socketv4_->local_endpoint().port())){
                    known_relays_->usable_relays.insert(rinfo);
                }
            }

            auto resp_buf = make_relay_handshake_rep_pakcet(requested_sid, chdr, dh.public_key());

            const auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));

            if(!sock || !sock->is_open()){
                LOG_ERROR(logger_, "Target socket is not open for endpoint {}", sender_endpoint.address().to_string());
                stats_reporter_->stats.on_malformed_packet();
                return;
            }

            LOG_INFO(logger_, "Sending response packet to endpoint {} via {}:{}",
                     sender_endpoint.address().to_string(), sock->local_endpoint().address().to_string(), sock->local_endpoint().port());

            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t bytes_xfer){
                    me->stats_reporter_->stats.on_packet_sent(bytes_xfer);
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelayHandshakeRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        case ControlMsgType::RELAY_DISCOVERY_REQ: {
            if(body_len < sizeof(RelayListReq)){
                LOG_WARNING(logger_, "RelayListReq payload too small.");
                stats_reporter_->stats.on_malformed_packet();
                return;
            }
            RelayListReq req{};
            std::memcpy(&req, msg_body, sizeof(RelayListReq));

            RelayListRes res{};
            uint16_t populated = 0;
            if(known_relays_){
                std::lock_guard<std::mutex> lock(known_relays_->registry_mutex_);
                for(const auto& rinfo: known_relays_->all_relays){
                    if(populated >= MAX_RELAY_LIST_SZ || populated >= req.relays_requested)
                        break;
                    if(rinfo.endpoint == sender_endpoint){
                        // don't send requester's ip to itself
                        continue;
                    }
                    if(rinfo.endpoint.address().is_v4()){
                        res.relays[populated].ipv4 = rinfo.endpoint.address().to_v4().to_uint();
                        res.relays[populated].port = rinfo.endpoint.port();
                        res.relays[populated].nat = 0;
                        res.relays[populated].bandwidth_tier = 0;
                        populated++;
                    }
                }
            }
            res.count = populated;

            auto resp_buf = make_relay_list_rep_packet(sid, chdr, res);

            // encrypt
            {
                auto hdr_size = sizeof(RoutingFlag) + sizeof(session_id_t);
                crypto::encrypt_layer_cr(sh_cr, resp_buf.data() + hdr_size, resp_buf.size() - hdr_size);
            }

            auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));
            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t bytes_xfer){
                    me->stats_reporter_->stats.on_packet_sent(bytes_xfer);
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelayListRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        case ControlMsgType::RELAY_SETUP_EXIT_REQ: {
            if(body_len < sizeof(RelaySetupExitReq)){
                LOG_WARNING(logger_, "RelaySetupExitReq payload too small.");
                stats_reporter_->stats.on_malformed_packet();
                return;
            }
            RelaySetupExitReq req{};
            std::memcpy(&req, msg_body, sizeof(RelaySetupExitReq));

            asio::ip::udp::endpoint exit_ep(
                asio::ip::address_v4(req.exit_ipv4),
                req.exit_port
            );

            // update maps
            sid_ei_umap_.put_if_absent(sid, ExitInfo{.endpoint = exit_ep});
            auto client_info = sid_ci_umap_.get(sid);
            if(client_info == nullptr){
                LOG_WARNING(logger_, "Client information is nullptr, asked to setup exit. sid: {}", sid);
                stats_reporter_->stats.on_malformed_packet();
                return;
            }
            cid_ci_umap_.put_if_absent(req.circuit_id, *client_info);

            RelaySetupExitRes res{.status = 0};
            auto resp_buf = make_relay_setup_exit_res_packet(sid, chdr, res);

            // encrypt
            {
                auto hdr_size = sizeof(RoutingFlag) + sizeof(session_id_t);
                crypto::encrypt_layer_cr(sh_cr, resp_buf.data() + hdr_size, resp_buf.size() - hdr_size);
            }

            auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));
            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t bytes_xfer){
                    me->stats_reporter_->stats.on_packet_sent(bytes_xfer);
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelaySetupExitRes: {}", ec.message());
                    }
                }
            );
            return;
        }


        case ControlMsgType::RELAY_CHANGE_EXIT_REQ: {
            if(body_len < sizeof(RelayChangeExitReq)){
                LOG_WARNING(logger_, "RelaySetupExitReq payload too small.");
                stats_reporter_->stats.on_malformed_packet();
                return;
            }
            RelayChangeExitReq req{};
            std::memcpy(&req, msg_body, sizeof(RelayChangeExitReq));

            auto cid = req.cid;

            asio::ip::address_v4 exit_addr(req.exit_ipv4);
            asio::ip::udp::endpoint exit_endpoint(exit_addr, req.exit_port);

            // update sid_ei_umap_
            ExitInfo new_exit{
                .endpoint = exit_endpoint,
                .sh_cr = sid_ei_umap_.get(sid)->sh_cr
            };
            sid_ei_umap_.put(sid, new_exit);

            // no need to update cid_ci_umap_ and sid_ci_umap_

            // send response
            {
                RelaySetupExitRes res{.status = 0};
                auto resp_buf = make_relay_setup_exit_res_packet(sid, chdr, res);
                // encrypt
                {
                    auto hdr_size = sizeof(RoutingFlag) + sizeof(session_id_t);
                    crypto::encrypt_layer_cr(sh_cr, resp_buf.data() + hdr_size, resp_buf.size() - hdr_size);
                }

                auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
                auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));
                sock->async_send_to(
                    asio::buffer(*send_data),
                    sender_endpoint,
                    [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t bytes_xfer){
                        me->stats_reporter_->stats.on_packet_sent(bytes_xfer);
                        if(ec){
                            LOG_ERROR(me->logger_, "Failed to send RelaySetupExitRes: {}", ec.message());
                        }
                    }
                );
            }

            return;
        }


        default:
            LOG_WARNING(logger_, "Unhandled client control message: {}", static_cast<int>(chdr.msg_type));
            stats_reporter_->stats.on_malformed_packet();
            break;
    }
}


std::vector<uint8_t> Relay::make_relay_setup_exit_res_packet(const session_id_t sid, const ControlHeader& chdr, const RelaySetupExitRes& res){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelaySetupExitRes));
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::RELAY_TO_CLIENT);
    std::memcpy(resp_buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    std::memcpy(resp_buf.data() + offset, &sid, sizeof(session_id_t));
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelaySetupExitRes));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(resp_buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader resp_chdr{};
    resp_chdr.msg_type = ControlMsgType::RELAY_SETUP_EXIT_RES;
    resp_chdr.flags = 0;
    resp_chdr.payload_len = static_cast<uint16_t>(sizeof(RelaySetupExitRes));
    resp_chdr.txn_id = chdr.txn_id;
    std::memcpy(resp_buf.data() + offset, &resp_chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    std::memcpy(resp_buf.data() + offset, &res, sizeof(RelaySetupExitRes));

    return resp_buf;
}


void Relay::process_packet_from_exit(ArenaSlot<IncomingCell> packet){
    forward_to_client(std::move(packet));
}


void Relay::forward_to_exit(ArenaSlot<IncomingCell> packet){
    std::shared_ptr<ExitInfo> exit_info = sid_ei_umap_.get(packet->sid);
    if(exit_info == nullptr){
        LOG_WARNING(logger_, "Dropping invalid packet, no session_id map found for sid: {}, cid:{}", packet->sid, packet->cid);
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    /*
    incoming packet:
        route_flag
        session_id
        {thdr, phdr, payload}
    outgoing packet:
        route_flag
        {thdr, phdr, payload}
    */
    std::array<asio::const_buffer, 2> outgoing = {
        asio::buffer(&packet->route_flag, sizeof(RoutingFlag)),
        asio::buffer(packet->payload.data() + packet->start_offset, packet->payload_bytes)
    };

    const std::shared_ptr<asio::ip::udp::socket> sock = (exit_info->endpoint.protocol() == asio::ip::udp::v4())
                                                            ? udp_socketv4_
                                                            : udp_socketv6_;

    sock->async_send_to(
        outgoing,
        exit_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), keep_alive = std::move(packet)](const boost::system::error_code& ec, size_t bytes_xfer){
            me->stats_reporter_->stats.on_packet_forwarded(bytes_xfer);
            if(ec){
                LOG_ERROR(me->logger_, "[Relay] Exit send failed: {}", ec.message());
                return;
            }
            if(bytes_xfer != keep_alive->outgoing_bytes){
                LOG_ERROR(me->logger_, "[Relay] Bytes sent mismatch: udp socket fail?");
            }
        }
    );
}


/*
incoming packet:
    route_flag
    {thdr, phdr, payload}
outgoing packet:
    route_flag
    session_id
    {thdr, phdr, payload}
*/
[[nodiscard]] static bool parse_packet_from_exit(const ArenaSlot<IncomingCell>& packet){
    if(packet->bytes_received < sizeof(RoutingFlag) + TRANSIT_HDR_SZ){
        return false;
    }

    TransitHeader thdr{};
    std::memcpy(&thdr, packet->payload.data() + sizeof(RoutingFlag), TRANSIT_HDR_SZ);
    packet->cid = thdr.circuit_id;

    packet->outgoing_bytes = packet->bytes_received + sizeof(session_id_t);
    packet->payload_bytes = packet->bytes_received - sizeof(RoutingFlag);
    packet->start_offset = sizeof(RoutingFlag);
    packet->route_flag = RoutingFlag::RELAY_TO_CLIENT;

    return true;
}


void Relay::forward_to_client(ArenaSlot<IncomingCell> packet){
    if(!parse_packet_from_exit(packet)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, size<5.");
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    std::shared_ptr<ClientInfo> client_info = cid_ci_umap_.get(packet->cid);
    if(client_info == nullptr){
        LOG_WARNING(logger_, "Dropping invalid packet, no circuit_id found.");
        stats_reporter_->stats.on_malformed_packet();
        return;
    }
    packet->sid = client_info->session_id;

    // encrypt(packet->payload + sizeof(routing_flag), client_info->sh_cr);
    crypto::encrypt_layer_cr(client_info->sh_cr, packet->payload.data() + packet->start_offset, packet->payload_bytes);

    /*
    incoming packet:
        route_flag
        {thdr, phdr, payload}
    outgoing packet:
        route_flag
        session_id
        {thdr, phdr, payload}
    */
    std::array<asio::const_buffer, 3> outgoing = {
        asio::buffer(&packet->route_flag, sizeof(RoutingFlag)),
        asio::buffer(&packet->sid, sizeof(session_id_t)),
        asio::buffer(packet->payload.data() + packet->start_offset, packet->payload_bytes)
    };

    std::shared_ptr<asio::ip::udp::socket> sock = (client_info->endpoint.protocol() == asio::ip::udp::v4())
                                                      ? udp_socketv4_
                                                      : udp_socketv6_;

    sock->async_send_to(
        outgoing,
        client_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), keep_alive = std::move(packet)]
        (const boost::system::error_code& ec, size_t bytes_xfer){
            me->stats_reporter_->stats.on_packet_forwarded(bytes_xfer);
            if(ec){
                LOG_ERROR(me->logger_, "Exit send failed: {}", ec.message());
                return;
            }
            if(keep_alive->outgoing_bytes != bytes_xfer){
                LOG_ERROR(me->logger_, "Bytes sent mismatch: udp socket fail?");
            }
        }
    );
}
