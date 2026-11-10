#include "src/node/roles/relay.hpp"
#include "src/network/comms/control.hpp"

#include <quill/LogMacros.h>
#include <quill/Frontend.h>

#include <utility>


Relay::Relay(asio::io_context& ioc,
             std::shared_ptr<asio::ip::udp::socket> sockv4,
             std::shared_ptr<asio::ip::udp::socket> sockv6,
             std::shared_ptr<RelaysInfoGlb> known_relays):
    ioc_(ioc),
    udp_socketv4_(std::move(sockv4)),
    udp_socketv6_(std::move(sockv6)),
    known_relays_(std::move(known_relays)){
    logger_ = quill::Frontend::get_logger("relay_logger");
}


Relay::~Relay() = default;


void Relay::start() const{
    LOG_INFO(logger_, "Relay starting.");
}


void Relay::stop(){
    // todo: signal clients about exit
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
    packet->sid = ntohl(net_sid);

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
    return true;
}


void Relay::process_packet_from_client(ArenaSlot<IncomingCell> packet, const asio::ip::udp::endpoint& sender_endpoint){
    if(!parse_upper_packet_from_client(packet)){
        LOG_ERROR(logger_, "Dropping faulty packet, route_packet, size<5.");
        return;
    }
    // todo: decrypt(packet->payload + sizeof(session_id), exit_info->sh_cr);
    if(!parse_cid_from_client(packet)){
        LOG_ERROR(logger_, "Dropping faulty packet, route_packet, unable to find cid.");
        return;
    }

    if(packet->cid == static_cast<circuit_id_t>(-1)){
        const uint8_t* control_data = packet->payload.data() + packet->start_offset + TRANSIT_HDR_SZ;
        const size_t control_len = packet->payload_bytes - TRANSIT_HDR_SZ;
        handle_control_from_client(packet->sid, control_data, control_len, sender_endpoint);
        return;
    }

    forward_to_exit(std::move(packet));
}


static std::vector<uint8_t> make_relay_handshake_rep_pakcet(const session_id_t sid, const ControlHeader& chdr){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayHandshakeRes));
    size_t offset = 0;

    resp_buf[offset] = static_cast<uint8_t>(RoutingFlag::RELAY_TO_CLIENT);
    offset += sizeof(RoutingFlag);

    for(size_t i = 0; i < sizeof(session_id_t); i++){
        resp_buf[offset + i] = static_cast<uint8_t>((sid >> (8 * (sizeof(session_id_t) - 1 - i))) & 0xFF);
    }
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayHandshakeRes));
    thdr.flags = 1;
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

    constexpr RelayHandshakeRes res{};
    std::memcpy(resp_buf.data() + offset, &res, sizeof(RelayHandshakeRes));

    return resp_buf;
}


static std::vector<uint8_t> make_relay_list_rep_packet(const session_id_t sid, const ControlHeader& chdr, const RelayListRes& res){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayListRes));
    size_t offset = 0;

    resp_buf[offset] = static_cast<uint8_t>(RoutingFlag::RELAY_TO_CLIENT);
    offset += sizeof(RoutingFlag);

    for(size_t i = 0; i < sizeof(session_id_t); i++){
        resp_buf[offset + i] = static_cast<uint8_t>((sid >> (8 * (sizeof(session_id_t) - 1 - i))) & 0xFF);
    }
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayListRes));
    thdr.flags = 1;
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


void Relay::handle_control_from_client(const session_id_t sid, const uint8_t* data, size_t len, const asio::ip::udp::endpoint& sender_endpoint){
    if(len < CONTROL_HDR_SZ){
        LOG_ERROR(logger_, "Dropping control packet from client: length too small ({})", len);
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
                LOG_ERROR(logger_, "RelayHandshakeReq payload too small.");
                return;
            }
            RelayHandshakeReq req{};
            std::memcpy(&req, msg_body, sizeof(RelayHandshakeReq));

            auto requested_sid = req.session_id_req;

            LOG_INFO(logger_, "HANDSHAKE: {}, endpoint: {}:{}", requested_sid, sender_endpoint.address().to_string(), sender_endpoint.port());

            const ClientInfo cinfo{
                .session_id = requested_sid,
                .endpoint   = sender_endpoint
            };
            // exit information is not yet confirmed.
            sid_ci_umap_.put_if_absent(requested_sid, cinfo);

            // update known_relays_
            if(known_relays_){
                auto& mut = known_relays_->registry_mutex_;
                std::lock_guard<std::mutex> lock(mut);
                auto rinfo = RelayInfo{.session_id = requested_sid, .endpoint = sender_endpoint};
                known_relays_->all_relays.insert(rinfo);
                if(!known_relays_->usable_relays.contains(rinfo) && is_relay_diverse(rinfo.endpoint, known_relays_->usable_relays)){
                    known_relays_->usable_relays.insert(rinfo);
                }
            }

            auto resp_buf = make_relay_handshake_rep_pakcet(requested_sid, chdr);

            const auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));

            if(!sock || !sock->is_open()){
                LOG_ERROR(logger_, "Target socket is not open for endpoint {}", sender_endpoint.address().to_string());
                return;
            }

            LOG_INFO(logger_, "Sending response packet to endpoint {} via {}:{}",
                     sender_endpoint.address().to_string(), sock->local_endpoint().address().to_string(), sock->local_endpoint().port());

            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t){
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelayHandshakeRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        case ControlMsgType::RELAY_DISCOVERY_REQ: {
            if(body_len < sizeof(RelayListReq)){
                LOG_ERROR(logger_, "RelayListReq payload too small.");
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
                    if(rinfo.endpoint.address().is_v4()){
                        res.relays[populated].ipv4 = htonl(rinfo.endpoint.address().to_v4().to_uint());
                        res.relays[populated].port = htons(rinfo.endpoint.port());
                        res.relays[populated].nat = 0;
                        res.relays[populated].bandwidth_tier = 0;
                        populated++;
                    }
                }
            }
            res.count = populated;

            auto resp_buf = make_relay_list_rep_packet(sid, chdr, res);

            auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));
            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t){
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelayListRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        case ControlMsgType::RELAY_SETUP_EXIT_REQ: {
            if(body_len < sizeof(RelaySetupExitReq)){
                LOG_ERROR(logger_, "RelaySetupExitReq payload too small.");
                return;
            }
            RelaySetupExitReq req{};
            std::memcpy(&req, msg_body, sizeof(RelaySetupExitReq));

            asio::ip::udp::endpoint exit_ep(
                asio::ip::address_v4(ntohl(req.exit_ipv4)),
                ntohs(req.exit_port)
            );

            // update maps
            sid_ei_umap_.put_if_absent(sid, ExitInfo{.endpoint = exit_ep});
            auto client_info = sid_ci_umap_.get(sid);
            if(client_info == nullptr){
                LOG_ERROR(logger_, "Client information is nullptr, asked to setup exit. sid: {}", sid);
                return;
            }
            cid_ci_umap_.put_if_absent(req.circuit_id, *client_info);

            RelaySetupExitRes res{.status = 0};
            auto resp_buf = make_relay_setup_exit_res_packet(sid, chdr, res);

            auto sock = (sender_endpoint.protocol() == asio::ip::udp::v4()) ? udp_socketv4_ : udp_socketv6_;
            auto send_data = std::make_shared<std::vector<uint8_t>>(std::move(resp_buf));
            sock->async_send_to(
                asio::buffer(*send_data),
                sender_endpoint,
                [me=shared_from_this(), keep_alive = send_data](const boost::system::error_code& ec, size_t){
                    if(ec){
                        LOG_ERROR(me->logger_, "Failed to send RelaySetupExitRes: {}", ec.message());
                    }
                }
            );
            return;
        }

        default:
            LOG_WARNING(logger_, "Unhandled client control message: {}", static_cast<int>(chdr.msg_type));
            break;
    }
}


std::vector<uint8_t> Relay::make_relay_setup_exit_res_packet(const session_id_t sid, const ControlHeader& chdr, const RelaySetupExitRes& res){
    std::vector<uint8_t> resp_buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelaySetupExitRes));
    size_t offset = 0;

    resp_buf[offset] = static_cast<uint8_t>(RoutingFlag::RELAY_TO_CLIENT);
    offset += sizeof(RoutingFlag);

    for(size_t i = 0; i < sizeof(session_id_t); i++){
        resp_buf[offset + i] = static_cast<uint8_t>((sid >> (8 * (sizeof(session_id_t) - 1 - i))) & 0xFF);
    }
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
        LOG_ERROR(logger_, "Dropping invalid packet, no session_id map found.");
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

    LOG_INFO(logger_, "Forwarding packet to exit, endpoint: {}:{}", exit_info->endpoint.address().to_string(), exit_info->endpoint.port());
    sock->async_send_to(
        outgoing,
        exit_info->endpoint,
        // packet in lambda to make sure it doesn't get destroyed.
        // ? compiler shouldn't theoretically optimize this packet out of the capture list.
        [me=shared_from_this(), keep_alive = std::move(packet)](const boost::system::error_code& ec, size_t bytes_xfer){
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
        return;
    }

    std::shared_ptr<ClientInfo> client_info = cid_ci_umap_.get(packet->cid);
    if(client_info == nullptr){
        LOG_WARNING(logger_, "Dropping invalid packet, no circuit_id found.");
        return;
    }
    packet->sid = htonl(client_info->session_id);

    // todo: encrypt(packet->payload + sizeof(circuit_id_t), client_info->sh_cr);

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
