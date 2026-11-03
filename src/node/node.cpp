#include "src/node/node.hpp"
#include "src/network/comms/control.hpp"

#include <stack>
#include <algorithm>
#include <random>
#include <chrono>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include "quill/LogMacros.h"
#include "quill/Frontend.h"


Node::Node(asio::io_context& ioc, const NodeRole role):
    role_(role),
    ioc_(ioc),
    listening_endpoint_(asio::ip::udp::endpoint(asio::ip::udp::v4(), 12345)),
    incoming_cell_pool_(16834, "node_logger"){
    udp_socketv4_ = std::make_shared<asio::ip::udp::socket>(ioc_);
    udp_socketv6_ = std::make_shared<asio::ip::udp::socket>(ioc_);
    logger_ = quill::Frontend::get_logger("node_logger");

    bootstrap_node_.endpoint = asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 8008);

    // todo: start client, start relay, start exit? based on the role.
    const bool is_client = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::CLIENT);
    const bool is_relay = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::RELAY);
    const bool is_exit = static_cast<uint8_t>(role_) & static_cast<uint8_t>(NodeRole::EXIT);

    if(is_client || is_relay)
        relays_info_glb_ = std::make_shared<RelaysInfoGlb>();

    if(is_client)
        client_ = std::make_shared<Client>(ioc_, udp_socketv4_, udp_socketv6_, relays_info_glb_);

    if(is_relay)
        relay_ = std::make_shared<Relay>(ioc_, udp_socketv4_, udp_socketv6_, relays_info_glb_);

    if(is_exit)
        exit_ = std::make_shared<Exit>(ioc_, udp_socketv4_, udp_socketv6_);
}


[[nodiscard]] asio::awaitable<bool> Node::start(){
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "start() called when running_.");
        co_return false;
    }

    boost::system::error_code ec;
    ec = udp_socketv4_->open(asio::ip::udp::v4(), ec);
    if(ec){
        LOG_ERROR(logger_, "udp_socketv4_ failed to open.");
        co_return false;
    }

    ec.clear();
    ec = udp_socketv6_->open(asio::ip::udp::v6(), ec);
    if(ec){
        LOG_ERROR(logger_, "udp_socketv6_ failed to open.");
        co_return false;
    }

    auto first_packetv4 = incoming_cell_pool_.alloc();
    listenv4(std::move(first_packetv4));
    auto first_packetv6 = incoming_cell_pool_.alloc();
    listenv6(std::move(first_packetv6));

    if(relays_info_glb_){
        if(CommError e = co_await establish_connection(bootstrap_node_, udp_socketv4_, relays_info_glb_); e){
            LOG_ERROR(logger_, "failed to talk to bill turner (bootstrap): {}", e.what());
            co_return false;
        }
        co_await populate_relays(relays_info_glb_, bootstrap_node_, udp_socketv4_);

        if(relays_info_glb_->usable_relays.empty()){
            LOG_ERROR(logger_, "failed to populate usable_relay list. all_relay count: {}", relays_info_glb_->all_relays.size());
            co_return false;
        }
    }

    if(client_ != nullptr){
        if(!client_->start()){
            LOG_ERROR(logger_, "Client not started.");
            co_return false;
        }
    }

    if(relay_ != nullptr)
        relay_->start();

    if(exit_ != nullptr)
        exit_->start();

    co_return true;
}


void Node::stop(){
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "stop() called when not running_.");
        return;
    }

    if(client_ != nullptr)
        client_->stop();

    if(relay_ != nullptr)
        relay_->stop();

    if(exit_ != nullptr)
        exit_->stop();

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
}


asio::awaitable<Node::CommError> Node::populate_relays(std::shared_ptr<RelaysInfoGlb> known_relays,
                                                       RelayInfo start_relay,
                                                       std::shared_ptr<asio::ip::udp::socket> udp_sockv4){
    if(!known_relays)
        co_return CommError(true, "known_relays is nullptr");
    if(start_relay.session_id == std::numeric_limits<session_id_t>::max())
        co_return CommError(true, "start_relay unconnected to populate relay list.");

    std::random_device rd;
    std::mt19937 rng(rd());

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

        // todo: only ipv4 for now
        if(current.endpoint.protocol() == asio::ip::udp::v6())
            continue;

        if(co_await establish_connection(current, udp_sockv4, known_relays))
            continue;

        if(!known_relays->usable_relays.contains(current) && is_relay_diverse(current.endpoint, known_relays->usable_relays)){
            known_relays->usable_relays.insert(current);
        }

        std::vector<RelayInfo> relay_list = co_await request_relay_list(current);

        // randomize
        std::ranges::shuffle(relay_list, rng);

        // choose RANDOM_SAMPLE_SIZE endpoints from this list
        size_t branch_count = 0;
        for(const auto& new_relay: relay_list){
            known_relays->all_relays.insert(new_relay);
            if(branch_count >= RANDOM_SAMPLE_SIZE && !visited.contains(new_relay)){
                visited.insert(new_relay);
                stk.push(new_relay);
                branch_count++;
            }
        }

        current_depth++;
    }

    co_return CommError(false);
}


bool Node::is_relay_diverse(const asio::ip::udp::endpoint& ep, const std::unordered_set<RelayInfo>& existing_relays){
    // fixme: can't we do anything for ipv6 :(
    // just rejecting ipv6
    if(!ep.address().is_v4())
        return false;

    const uint32_t candidate_ip = ep.address().to_v4().to_uint();
    const uint32_t candidate_subnet = candidate_ip & 0xFFFF0000; // /16 mask

    for(const auto& [session_id, endpoint]: existing_relays){
        if(endpoint.address().is_v4()){
            const uint32_t existing_ip = endpoint.address().to_v4().to_uint();
            if(const uint32_t existing_subnet = existing_ip & 0xFFFF0000; candidate_subnet == existing_subnet){
                return false; // reject nodes sharing the same /16 subnet
            }
        }
    }
    return true;
}


asio::awaitable<Node::CommError> Node::establish_connection(RelayInfo relay,
                                                            std::shared_ptr<asio::ip::udp::socket> udp_sockv4,
                                                            std::shared_ptr<RelaysInfoGlb> relays_info_glb){
    // fixme: ipv6
    if(relay.endpoint.protocol() == asio::ip::udp::v6())
        co_return CommError(true, "relay.endpoint is of type ipv6");

    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<session_id_t> dist(0, std::numeric_limits<session_id_t>::max() - 1);

    relay.session_id = dist(gen);

    const auto packet = make_connection_packet(relay);

    auto timeout = udp_comms_config::start_timeout;

    std::vector<uint8_t> response_buf(1024);

    auto executor = co_await asio::this_coro::executor;

    for(size_t attempt = 1; attempt <= udp_comms_config::max_attempts; attempt++){
        try{
            asio::ip::udp::endpoint sender_endpoint;
            co_await udp_sockv4->async_send_to(asio::buffer(packet), relay.endpoint, asio::use_awaitable);

            asio::steady_timer timer(executor, timeout);

            // fixme: experimental
            // wait for timer / response
            using namespace boost::asio::experimental::awaitable_operators;
            auto result = co_await (
                async_wait_for_response(relay.session_id, asio::use_awaitable, relays_info_glb)
                ||
                timer.async_wait(asio::use_awaitable)
            );

            if(result.index() == 0){
                // todo: parse response and return
                co_return CommError(false);
            }

            auto& mut = relays_info_glb->registry_mutex_;
            std::lock_guard<std::mutex> lock(mut);
            relays_info_glb->pending_requests_.erase(relay.session_id);
        }
        catch(const std::exception& ex){
            co_return CommError(true, std::string("establish_connection failed : ") + ex.what());
        }

        timeout *= 2;
    }

    relay.session_id = static_cast<session_id_t>(-1);
    co_return false;
}


void Node::listenv4(ArenaSlot<IncomingCell> packet){
    udp_socketv4_->async_receive_from(
        asio::buffer(packet->payload),
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
            pkt->bytes_received = bytes_received;
            me->loop_listen(std::move(pkt), ec, true);
        }
    );
}


void Node::listenv6(ArenaSlot<IncomingCell> packet){
    udp_socketv6_->async_receive_from(
        asio::buffer(packet->payload),
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
            pkt->bytes_received = bytes_received;
            me->loop_listen(std::move(pkt), ec, false);
        }
    );
}


void Node::loop_listen(ArenaSlot<IncomingCell> packet, const boost::system::error_code& ec, bool ipv4){
    if(ec){
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
        return;
    }
    packet->route_flag = static_cast<RoutingFlag>(packet->payload[0]);

    switch(packet->route_flag){
        case RoutingFlag::CLIENT_TO_RELAY: {
            relay_->process_packet_from_client(std::move(packet));
            return;
        }
        case RoutingFlag::EXIT_TO_RELAY: {
            relay_->process_packet_from_exit(std::move(packet));
            return;
        }
        case RoutingFlag::RELAY_TO_CLIENT: {
            client_->process_incoming_packet(std::move(packet));
            return;
        }
        case RoutingFlag::RELAY_TO_EXIT: {
            exit_->process_incoming_packet(std::move(packet));
            return;
        }
        default: {
            LOG_WARNING(logger_, "Dropping faulty packet, invalid routing flag.");
            return;
        }
    }
}


void Node::resume_establishing_connection(session_id_t session_id,
                                          std::vector<uint8_t> payload,
                                          std::shared_ptr<RelaysInfoGlb> relays_info_glb){
    RelaysInfoGlb::ResponseHandler handler;
    {
        auto& mut = relays_info_glb->registry_mutex_;
        std::lock_guard<std::mutex> lock(mut);
        auto it = relays_info_glb->pending_requests_.find(session_id);
        if(it != relays_info_glb->pending_requests_.end()){
            handler = std::move(it->second);
            relays_info_glb->pending_requests_.erase(it);
        }
    }

    if(handler){
        // executing this handler resumes the waiting coroutine (establish_connection)
        handler(boost::system::error_code{}, std::move(payload));
    }
}
