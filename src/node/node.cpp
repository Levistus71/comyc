#include "src/node/node.hpp"
#include "src/network/comms/control.hpp"
#include "src/encryption/encryption.hpp"
#include "src/gui/telemetry/demo_reporter.hpp"

#include <stack>
#include <algorithm>
#include <random>
#include <chrono>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include "quill/LogMacros.h"
#include "quill/Frontend.h"
#include "fmt/format.h"


Node::Node(asio::io_context& ioc, std::shared_ptr<cli::CliOptions> options):
    role_(options->role),
    ioc_(ioc),
    incoming_cell_pool_(Settings::ARENA_POOL_SIZE, "node_logger"){
    logger_ = quill::Frontend::get_logger("node_logger");
    stats_reporter_ = std::make_shared<network_stats::StatsReporter>(ioc_, logger_);
    using udp = asio::ip::udp;

    udp_socketv4_ = std::make_shared<udp::socket>(ioc_);
    udp_socketv6_ = std::make_shared<udp::socket>(ioc_);

    if(options->specified_bootstrap)
        bootstrap_node_.endpoint = udp::endpoint(asio::ip::make_address(options->bootstrap_ip), options->bootstrap_port);
    else
        bootstrap_node_.endpoint = udp::endpoint(asio::ip::make_address(Settings::BOOTSTRAP_IP), Settings::BOOTSTRAP_PORT);

    sender_endpoint_ = std::make_shared<asio::ip::udp::endpoint>();

    const bool is_pure_client = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::CLIENT);
    const bool is_relay = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::RELAY);
    const bool is_client = is_pure_client || is_relay;
    dead_client_ = !is_pure_client && is_relay;
    const bool is_exit = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::EXIT);

    relays_info_glb_ = std::make_shared<RelaysInfoGlb>();

    if(is_client){
        asio::ip::udp::endpoint exit_endpoint;
        bool inited = false;
        if(options->specified_exit){
            try{
                exit_endpoint = asio::ip::udp::endpoint(asio::ip::make_address(options->exit_ip), options->exit_port);
                inited = true;
            }
            catch(...){
                LOG_ERROR(logger_, "Specified exit address unable to be converted to valid address: {}", options->exit_ip);
                LOG_ERROR(logger_, "Using default exit address.");
            }
        }
        if(!inited){
            // todo: change this from google dns
            exit_endpoint = asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 6969);
        }

        client_ = std::make_shared<Client>(ioc_, udp_socketv4_, udp_socketv6_, relays_info_glb_, exit_endpoint, stats_reporter_);
    }

    if(is_relay)
        relay_ = std::make_shared<Relay>(ioc_, udp_socketv4_, udp_socketv6_, relays_info_glb_, stats_reporter_);

    if(is_exit)
        exit_ = std::make_shared<Exit>(ioc_, udp_socketv4_, udp_socketv6_, relays_info_glb_, stats_reporter_);
}


[[nodiscard]] asio::awaitable<bool> Node::start(std::shared_ptr<cli::CliOptions> options){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "start() called when running_.");
        co_return false;
    }

    stats_reporter_->start();

    if(options->demo_mode){
        if(telemetry::DemoReporter::instance().init(ioc_, udp_socketv4_, options, logger_)){
            LOG_INFO(logger_, "Demo reporter initialized towards {}:{}", options->demo_host_ip, options->demo_host_port);
        }
        else{
            LOG_ERROR(logger_, "Demo reporter failed to start.");
            co_return false;
        }
    }

    using udp = asio::ip::udp;
    boost::system::error_code ec;
    if((ec = udp_socketv4_->open(asio::ip::udp::v4(), ec))){
        LOG_ERROR(logger_, "Failed to open udp_socketv4, aborting. ec: {}", ec.what());
        co_return false;
    }
    if(options->listen_port != 0){
        if((ec = udp_socketv4_->bind(udp::endpoint(udp::v4(), options->listen_port), ec))){
            LOG_ERROR(logger_, "UDP socket v4 binding failed for port {}, falling back to ephemeral. ec: {}",
                      options->listen_port, ec.what());

            if((ec = udp_socketv4_->bind(udp::endpoint(udp::v4(), 0), ec))){
                LOG_ERROR(logger_, "Failed to assign v4 fallback ephemeral port, aborting. ec: {}", ec.what());
                co_return false;
            }
        }
    }
    else{
        if((ec = udp_socketv4_->bind(udp::endpoint(udp::v4(), 0), ec))){
            LOG_ERROR(logger_, "Failed to bind v4 to ephemeral port, aborting. ec: {}", ec.what());
            co_return false;
        }
    }

    // fixme: port will be assigned to ipv4 only for now
    ec.clear();
    if(udp_socketv6_->open(asio::ip::udp::v6(), ec)){
        LOG_ERROR(logger_, "Failed to open udp_socketv6, aborting. ec: {}", ec.what());
        co_return false;
    }
    if((ec = udp_socketv6_->bind(udp::endpoint(udp::v6(), 0), ec))){
        LOG_ERROR(logger_, "Failed to bind v6 to ephemeral port, aborting. ec: {}", ec.what());
        co_return false;
    }

    auto first_packetv4 = incoming_cell_pool_.alloc();
    listenv4(std::move(first_packetv4));
    auto first_packetv6 = incoming_cell_pool_.alloc();
    listenv6(std::move(first_packetv6));

    LOG_INFO(logger_, "Started v4 listening on port: {}", udp_socketv4_->local_endpoint().port());
    LOG_INFO(logger_, "Started v6 listening on port: {}", udp_socketv6_->local_endpoint().port());

    if(client_ || relay_){
        if(options->bootstrap_node){
            LOG_INFO(logger_, "I'm Bootstrap Bill, skipping establish_connection...");
        }
        else{
            if(CommError e = co_await establish_connection(bootstrap_node_, udp_socketv4_, relays_info_glb_, logger_, stats_reporter_); e){
                LOG_ERROR(logger_, "failed to talk to Bill Turner (bootstrap): {}", e.what());
                co_return false;
            }
            LOG_INFO(logger_, "Successfully connected to Bill Turner (bootstrap)");
            co_await populate_relays(relays_info_glb_, bootstrap_node_, udp_socketv4_, logger_, client_, stats_reporter_);
        }
    }

    if(client_ != nullptr){
        if(!co_await client_->start(options->hijack_utun, dead_client_)){
            LOG_ERROR(logger_, "Client not started.");
            co_return false;
        }
    }

    if(relay_ != nullptr)
        relay_->start();

    if(exit_ != nullptr){
        if(!exit_->start()){
            LOG_ERROR(logger_, "Exit not started.");
            co_return false;
        }
    }

    co_return true;
}


asio::awaitable<void> Node::stop(){
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "stop() called when not running_.");
        co_return;
    }

    stats_reporter_->stop();

    telemetry::DemoReporter::instance().stop();

    if(client_ != nullptr)
        client_->stop();

    if(relay_ != nullptr)
        relay_->stop();

    if(exit_ != nullptr){
        co_await exit_->stop();
    }

    boost::system::error_code ec;
    ec = udp_socketv4_->close(ec);
    if(ec){
        LOG_ERROR(logger_, "Error closing udp socket v4: {}", ec.message());
    }

    ec.clear();
    ec = udp_socketv6_->close(ec);
    if(ec){
        LOG_ERROR(logger_, "Error closing udp socket v6: {}", ec.message());
    }

    LOG_INFO(logger_, "Stopped.");
}


// todo: known_relay lock (since it's called from start() right now, its safe, it might not be in the future)
asio::awaitable<Node::CommError> Node::populate_relays(std::shared_ptr<RelaysInfoGlb> known_relays,
                                                       RelayInfo start_relay,
                                                       std::shared_ptr<asio::ip::udp::socket> udp_sockv4,
                                                       quill::Logger* logger,
                                                       std::shared_ptr<Client> client,
                                                       std::shared_ptr<network_stats::StatsReporter> stats_reporter){
    if(!known_relays)
        co_return CommError(true, "known_relays is nullptr");
    if(start_relay.session_id == std::numeric_limits<session_id_t>::max())
        co_return CommError(true, "start_relay unconnected to populate relay list.");

    known_relays->all_relays.insert(start_relay);

    std::mt19937& rng = RandomGen::gen_;

    std::unordered_set<RelayInfo> visited;
    std::stack<RelayInfo> stk;

    stk.push(start_relay);
    visited.insert(start_relay);

    constexpr size_t MAX_DEPTH = 10;
    constexpr size_t RANDOM_SAMPLE_SIZE = 4; // how many relays we choose every dfs step

    size_t current_depth = 0;

    while(!stk.empty() && current_depth < MAX_DEPTH && known_relays->usable_relays.size() < DESIRED_RELAY_COUNT){
        RelayInfo current = stk.top();
        stk.pop();

        // fixme: only ipv4 for now
        if(current.endpoint.protocol() == asio::ip::udp::v6())
            continue;

        if(!current.is_connected()){
            LOG_INFO(logger, "Trying to establish connection new relay");
            if(co_await establish_connection(current, udp_sockv4, known_relays, logger, stats_reporter))
                continue;
            auto it = known_relays->all_relays.find(current);
            if(it != known_relays->all_relays.end()){
                it->session_id = current.session_id;
                it->sh_cr = current.sh_cr;
            }
            else{
                LOG_DEBUG(logger, "logic error");
                known_relays->all_relays.insert(current);
            }
        }

        if(!known_relays->usable_relays.contains(current) && is_relay_diverse(current.endpoint,
                                                                              known_relays->usable_relays,
                                                                              udp_sockv4->local_endpoint().port())){
            known_relays->usable_relays.insert(current);
        }

        client->update_relays();


        LOG_INFO(logger, "requesting relay list from: {}, session_id: {}",
                 current.to_string(), current.session_id);
        std::vector<RelayInfo> relay_list = co_await request_relay_list(current, udp_sockv4, known_relays, logger, stats_reporter);

        // randomize
        std::ranges::shuffle(relay_list, rng);

        // choose RANDOM_SAMPLE_SIZE endpoints from this list
        size_t branch_count = 0;
        for(const auto& new_relay: relay_list){
            known_relays->all_relays.insert(new_relay);
            if(branch_count <= RANDOM_SAMPLE_SIZE && !visited.contains(new_relay)){
                visited.insert(new_relay);
                stk.push(new_relay);
                branch_count++;
            }
        }

        current_depth++;
    }

    // if the dfs didn't result in desired_relay_count usable relays
    for(const auto& relay: known_relays->all_relays){
        if(known_relays->usable_relays.size() >= DESIRED_RELAY_COUNT)
            break;
        if(known_relays->usable_relays.contains(relay) || !is_relay_diverse(relay.endpoint,
                                                                            known_relays->usable_relays,
                                                                            udp_sockv4->local_endpoint().port()))
            continue;
        if(co_await establish_connection(relay, udp_sockv4, known_relays, logger, stats_reporter)){
            LOG_WARNING(logger, "Couldn't connect to relay: {}", relay.to_string());
            continue;
        }
        known_relays->usable_relays.insert(relay);
    }

    // LOG
    std::string known_str;
    for(const auto& relay: known_relays->all_relays){
        known_str += fmt::format("\n  - sid: {}, endpoint: {}", relay.session_id, relay.to_string());
    }

    std::string usable_str;
    for(const auto& relay: known_relays->usable_relays){
        usable_str += fmt::format("\n  - sid: {}, endpoint: {}", relay.session_id, relay.to_string());
    }

    client->update_relays();
    LOG_INFO(logger, "Populated Relays Summary:\nAll Known Relays:{}\nUsable (Connected) Relays:{}", known_str, usable_str);

    co_return CommError(false);
}


std::vector<uint8_t> Node::make_connection_packet(const RelayInfo& relay, txn_id_t txn_id, const std::array<uint8_t, 32>& pubkey){
    std::vector<uint8_t> buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayHandshakeReq));

    size_t offset = 0;

    // client to relay flag
    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::CLIENT_TO_RELAY);
    std::memcpy(buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    // session_id = -1
    std::fill_n(&buf[offset], sizeof(session_id_t), static_cast<session_id_t>(-1));
    offset += sizeof(session_id_t);

    // thdr (circuit_id = -1 for relay control)
    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayHandshakeReq));
    thdr.flags = static_cast<uint16_t>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    // control_header
    ControlHeader chdr{};
    chdr.msg_type = ControlMsgType::RELAY_HANDSHAKE_REQ;
    chdr.flags = 0;
    chdr.payload_len = static_cast<uint16_t>(sizeof(RelayHandshakeReq));
    chdr.txn_id = txn_id;
    std::memcpy(buf.data() + offset, &chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    // control body
    RelayHandshakeReq req{};
    req.session_id_req = relay.session_id;
    std::memcpy(req.public_key, pubkey.data(), sizeof(req.public_key));
    std::memcpy(buf.data() + offset, &req, sizeof(RelayHandshakeReq));

    return buf;
}


std::vector<uint8_t> Node::make_request_relay_list_packet(RelayInfo& relay, txn_id_t txn_id){
    // packet: RoutingFlag + session_id + TransitHeader + ControlHeader + RelayListReq
    std::vector<uint8_t> buf(sizeof(RoutingFlag) + sizeof(session_id_t) + TRANSIT_HDR_SZ + CONTROL_HDR_SZ + sizeof(RelayListReq));
    size_t offset = 0;

    auto route_flag = static_cast<std::underlying_type_t<RoutingFlag>>(RoutingFlag::CLIENT_TO_RELAY);
    std::memcpy(buf.data() + offset, &route_flag, sizeof(route_flag));
    offset += sizeof(route_flag);

    std::memcpy(buf.data() + offset, &relay.session_id, sizeof(session_id_t));
    offset += sizeof(session_id_t);

    TransitHeader thdr{};
    thdr.circuit_id = static_cast<circuit_id_t>(-1);
    thdr.frame_len = static_cast<uint16_t>(CONTROL_HDR_SZ + sizeof(RelayListReq));
    thdr.flags = static_cast<std::underlying_type_t<ThdrFlag>>(ThdrFlag::CONTROL);
    thdr.payload_tier = PayloadTier::TIER_64;
    std::memcpy(buf.data() + offset, &thdr, TRANSIT_HDR_SZ);
    offset += TRANSIT_HDR_SZ;

    ControlHeader chdr{};
    chdr.msg_type = ControlMsgType::RELAY_DISCOVERY_REQ;
    chdr.flags = 0;
    chdr.payload_len = static_cast<uint16_t>(sizeof(RelayListReq));
    chdr.txn_id = txn_id;
    std::memcpy(buf.data() + offset, &chdr, CONTROL_HDR_SZ);
    offset += CONTROL_HDR_SZ;

    RelayListReq req{};
    req.relays_requested = MAX_RELAY_LIST_SZ;
    std::memcpy(buf.data() + offset, &req, sizeof(RelayListReq));

    return buf;
}


asio::awaitable<std::vector<RelayInfo>> Node::request_relay_list(RelayInfo& relay,
                                                                 std::shared_ptr<asio::ip::udp::socket> udp_sockv4,
                                                                 std::shared_ptr<RelaysInfoGlb> relays_info_glb,
                                                                 quill::Logger* logger,
                                                                 std::shared_ptr<network_stats::StatsReporter> stats_reporter){
    std::vector<RelayInfo> result_relays;
    if(relay.session_id == static_cast<session_id_t>(-1) || !udp_sockv4 || !relays_info_glb){
        co_return result_relays;
    }

    txn_id_t txn_id = RandomGen::gen_txn_id();
    auto request_packet = make_request_relay_list_packet(relay, txn_id);

    // encrypt
    {
        auto hdr_size = sizeof(RoutingFlag) + sizeof(session_id_t);
        crypto::encrypt_layer_cr(relay.sh_cr, request_packet.data() + hdr_size, request_packet.size() - hdr_size);
    }

    auto response = co_await control_send_and_wait_udp(udp_sockv4, request_packet, relay.endpoint, txn_id, relays_info_glb, logger, stats_reporter);

    if(std::holds_alternative<std::vector<uint8_t>>(response)){
        // client::process_incoming_packet already parsed the raw packet. we just get the response body.
        std::vector<uint8_t> payload = std::get<std::vector<uint8_t>>(std::move(response));
        if(payload.size() >= sizeof(RelayListRes)){
            RelayListRes res{};
            std::memcpy(&res, payload.data(), sizeof(RelayListRes));
            size_t count = std::min<size_t>(res.count, MAX_RELAY_LIST_SZ);
            for(size_t i = 0; i < count; i++){
                const auto& rec = res.relays[i];
                if(rec.ipv4 == 0)
                    continue;
                RelayInfo rinfo;
                rinfo.session_id = static_cast<session_id_t>(-1);
                rinfo.endpoint = asio::ip::udp::endpoint(asio::ip::address_v4(rec.ipv4), rec.port);
                result_relays.push_back(rinfo);
            }
        }
    }

    co_return result_relays;
}


asio::awaitable<Node::CommError> Node::establish_connection(const RelayInfo& relay,
                                                            std::shared_ptr<asio::ip::udp::socket> udp_sockv4,
                                                            std::shared_ptr<RelaysInfoGlb> relays_info_glb,
                                                            quill::Logger* logger,
                                                            std::shared_ptr<network_stats::StatsReporter> stats_reporter){
    // fixme: ipv6
    if(relay.endpoint.protocol() == asio::ip::udp::v6())
        co_return CommError(true, "relay.endpoint is of type ipv6");

    relay.session_id = RandomGen::gen_session_id();
    const txn_id_t txn_id = RandomGen::gen_txn_id();

    LOG_INFO(logger, "Starting establishing connection to {}, session_id: {}",
             relay.to_string(), relay.session_id);

    crypto::EphemeralDH dh;
    if(!dh.initialized){
        LOG_ERROR(logger, "Failed to initialize ephemeral DH for relay connection");
        stats_reporter->stats.on_crypto_failure();
        co_return CommError(true, "crypto DH init failed");
    }

    const auto packet = make_connection_packet(relay, txn_id, dh.public_key());

    LOG_INFO(logger, "Trying to connect via udp, max attempts : {}", UDP_Comms_Settings::max_attempts);
    auto res = co_await control_send_and_wait_udp(udp_sockv4, packet, relay.endpoint, txn_id, relays_info_glb, logger, stats_reporter);

    if(std::holds_alternative<std::vector<uint8_t>>(res)){
        LOG_INFO(logger, "Established connection: {}", relay.to_string());
        auto response = std::get<std::vector<uint8_t>>(std::move(res));
        // client::process_incoming_packet already parsed the raw packet. we just get the response body.
        if(response.size() >= sizeof(RelayHandshakeRes)){
            RelayHandshakeRes handshake_res{};
            std::memcpy(&handshake_res, response.data(), sizeof(RelayHandshakeRes));

            crypto::PubKey256 peer_pubkey{};
            std::memcpy(peer_pubkey.data(), handshake_res.public_key, sizeof(peer_pubkey));

            if(!dh.compute_shared_secret(peer_pubkey, relay.sh_cr)){
                LOG_ERROR(logger, "Failed to compute shared secret SH_CR with relay");
                stats_reporter->stats.on_crypto_failure();
                co_return CommError(true, "shared secret derivation failed");
            }
            LOG_INFO(logger, "Derived shared secret SH_CR with relay successfully");
        }
        co_return false;
    }

    LOG_INFO(logger, "Establish connection failed.");
    co_return std::get<CommError>(res);
}


asio::awaitable<Node::ControlResult> Node::control_send_and_wait_udp(std::shared_ptr<asio::ip::udp::socket> udp_sockv4,
                                                                     std::vector<uint8_t> packet,
                                                                     asio::ip::udp::endpoint endpoint,
                                                                     txn_id_t txn_id,
                                                                     std::shared_ptr<RelaysInfoGlb> relays_info_glb,
                                                                     quill::Logger* logger,
                                                                     std::shared_ptr<network_stats::StatsReporter> stats_reporter){
    auto executor = co_await asio::this_coro::executor;
    auto timeout = UDP_Comms_Settings::start_timeout;

    struct RAII_cleanup{
        std::shared_ptr<RelaysInfoGlb> info;
        txn_id_t id;


        ~RAII_cleanup(){
            if(info){
                std::lock_guard<std::mutex> lock(info->registry_mutex_);
                info->pending_requests_.erase(id);
            }
        }
    } cleanup{relays_info_glb, txn_id};

    for(size_t attempt = 1; attempt <= UDP_Comms_Settings::max_attempts; attempt++){
        try{
            co_await udp_sockv4->async_send_to(asio::buffer(packet), endpoint, asio::use_awaitable);
            stats_reporter->stats.on_packet_sent(packet.size());

            asio::steady_timer timer(executor, timeout);

            // fixme: experimental
            // wait for timer / response
            using namespace boost::asio::experimental::awaitable_operators;
            auto result = co_await (
                async_wait_for_response(txn_id, asio::use_awaitable, relays_info_glb)
                ||
                timer.async_wait(asio::use_awaitable)
            );

            if(result.index() == 0){
                timer.cancel();
                stats_reporter->stats.on_packet_received(std::get<0>(result).size());
                auto response_packet = std::get<0>(std::move(result));
                co_return response_packet;
            }

            auto& mut = relays_info_glb->registry_mutex_;
            std::lock_guard<std::mutex> lock(mut);
            relays_info_glb->pending_requests_.erase(txn_id);
        }
        catch(const std::exception& /*ex*/){
            // retry on exception
        }

        timeout *= 2;
    }

    LOG_INFO(logger, "Couldn't receive response, max attempts reached.");
    co_return CommError(true, "didn't receive response, max attempts reached");
}


void Node::listenv4(ArenaSlot<IncomingCell> packet){
    if(!packet){
        LOG_CRITICAL(logger_, "listenv4 was called with null packet.");
        return;
    }

    auto recv_buf = asio::buffer(packet->payload);

    udp_socketv4_->async_receive_from(
        recv_buf,
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
            pkt->bytes_received = bytes_received;
            me->stats_reporter_->stats.on_packet_received(bytes_received);
            me->loop_listen(std::move(pkt), ec, true);
        }
    );
}


void Node::listenv6(ArenaSlot<IncomingCell> packet){
    if(!packet){
        LOG_CRITICAL(logger_, "listenv6 was called with null packet.");
        return;
    }

    auto recv_buf = asio::buffer(packet->payload);

    udp_socketv6_->async_receive_from(
        recv_buf,
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
            pkt->bytes_received = bytes_received;
            me->stats_reporter_->stats.on_packet_received(bytes_received);
            me->loop_listen(std::move(pkt), ec, false);
        }
    );
}


void Node::loop_listen(ArenaSlot<IncomingCell> packet, const boost::system::error_code& ec, bool ipv4){
    if(ec){
        if(ec.message() == "Operation canceled"){
            LOG_INFO(logger_, "Stopped listening.");
            return;
        }
        LOG_ERROR(logger_, "Packet receive failed in loop_listen(): {}", ec.message());
        return;
    }

    ArenaSlot<IncomingCell> new_packet = incoming_cell_pool_.alloc();
    asio::ip::udp::endpoint endpoint = std::move(*sender_endpoint_.get());
    if(ipv4)
        listenv4(std::move(new_packet));
    else
        listenv6(std::move(new_packet));

    route_packet(std::move(packet), endpoint);
}


void Node::route_packet(ArenaSlot<IncomingCell> packet, asio::ip::udp::endpoint endpoint) const{
    if(packet->bytes_received < sizeof(RoutingFlag)){
        LOG_WARNING(logger_, "Dropping faulty packet, route_packet, size<1.");
        stats_reporter_->stats.on_malformed_packet();
        return;
    }

    using FlagType = std::underlying_type_t<RoutingFlag>;
    FlagType raw_flag;
    std::memcpy(&raw_flag, packet->payload.data(), sizeof(FlagType));
    packet->route_flag = static_cast<RoutingFlag>(raw_flag);

    switch(packet->route_flag){
        case RoutingFlag::CLIENT_TO_RELAY: {
            if(relay_){
                relay_->process_packet_from_client(std::move(packet), endpoint);
            }
            return;
        }
        case RoutingFlag::EXIT_TO_RELAY: {
            if(relay_){
                relay_->process_packet_from_exit(std::move(packet));
            }
            return;
        }
        case RoutingFlag::RELAY_TO_CLIENT: {
            if(client_){
                client_->process_incoming_packet(std::move(packet));
            }
            return;
        }
        case RoutingFlag::RELAY_TO_EXIT: {
            if(exit_){
                exit_->process_incoming_packet(std::move(packet), endpoint);
            }
            return;
        }
        default: {
            return;
        }
    }
}


void Node::resume_control_operation(txn_id_t txn_id,
                                    std::vector<uint8_t> payload,
                                    std::shared_ptr<RelaysInfoGlb> relays_info_glb){
    RelaysInfoGlb::ResponseHandler our_handler;
    {
        auto& mut = relays_info_glb->registry_mutex_;
        std::lock_guard<std::mutex> lock(mut);
        auto it = relays_info_glb->pending_requests_.find(txn_id);
        if(it != relays_info_glb->pending_requests_.end()){
            our_handler = std::move(it->second);
            relays_info_glb->pending_requests_.erase(it);
        }
    }

    if(our_handler){
        // executing this our_handler resumes the waiting coroutine (which was put there by
        // async_wait_for_response (node.hpp)
        our_handler(boost::system::error_code{}, std::move(payload));
    }
}
