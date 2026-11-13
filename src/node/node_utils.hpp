#pragma once
#include <functional>
#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <random>

#include "src/network/comms/control.hpp"
#include <src/node/buffers/arena_allocator.hpp>
#include <src/node/buffers/reorder_buffer.hpp>
#include "src/network/packets/cell.hpp"

#include <boost/container_hash/hash.hpp>
#include <boost/asio.hpp>
#include <utility>


#if !defined(__cpp_lib_atomic_shared_ptr) || __cpp_lib_atomic_shared_ptr < 201711L
#error "C++ library toolchain doesn't support std::atomic<std::shared_ptr>"
#endif

namespace asio = boost::asio;


template<typename T>
struct is_shared_ptr : std::false_type{};


template<typename T>
struct is_shared_ptr<std::shared_ptr<T>> : std::true_type{};


template<typename T>
concept SharedPtr = is_shared_ptr<T>::value;


template<
    class Key,
    class Val,
    class Hash = std::hash<Key>,
    class KeyEqual = std::equal_to<Key>,
    class Allocator = std::allocator<std::pair<const Key, Val>>>
class RCU_UMap{
public:
    using MapType = std::unordered_map<Key, Val, Hash, KeyEqual, Allocator>;


    RCU_UMap();


    using return_type = std::conditional_t<SharedPtr<Val>, Val, std::shared_ptr<Val>>;


    return_type get(const Key& k);


    void put(const Key& k, const Val& v);


    void put(const Key& k, Val&& v);


    std::pair<return_type, bool> put_if_absent(const Key& k, const Val& v);


    std::pair<return_type, bool> put_if_absent(const Key& k, Val&& v);


    void erase(const Key& key);

private:
    std::atomic<std::shared_ptr<MapType>> umap_;
    std::mutex write_lock_;
};


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::RCU_UMap(){
    auto initial_map = std::make_shared<MapType>();
    umap_.store(initial_map);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
typename RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::return_type RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::get(const Key& k){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            // keeps local_umap alive (control block of shared_ptr is of local_umap's)
            // creates the potiner to it->second (the pointer points to it->second though)
            if constexpr(SharedPtr<Val>){
                // return copy of stored shared_ptr directly. to avoid .get().get()
                return it->second;
            }
            else{
                // keep local_umap alive, point to value.
                return std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second));
            }
        }
    }
    return nullptr;
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, const Val& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? std::make_shared<MapType>(*current_umap) : std::make_shared<MapType>();

    (*new_umap)[k] = v;

    umap_.store(new_umap);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, Val&& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? std::make_shared<MapType>(*current_umap) : std::make_shared<MapType>();

    (*new_umap)[k] = std::move(v);

    umap_.store(new_umap);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::pair<typename RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::return_type, bool> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put_if_absent(const Key& k, const Val& v){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            if constexpr(SharedPtr<Val>){
                return {it->second, false};
            }
            else{
                return {std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second)), false};
            }
        }
    }

    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(current){
        auto it = current->find(k);
        if(it != current->end()){
            if constexpr(SharedPtr<Val>){
                return {it->second, false};
            }
            else{
                return {std::shared_ptr<Val>(current, const_cast<Val*>(&it->second)), false};
            }
        }
    }

    auto new_map = current ? std::make_shared<MapType>(*current) : std::make_shared<MapType>();
    auto [it, inserted] = new_map->emplace(k, v);

    umap_.store(new_map, std::memory_order_release);

    if constexpr(SharedPtr<Val>){
        return {it->second, true};
    }
    else{
        return {std::shared_ptr<Val>(new_map, &it->second), true};
    }
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::pair<typename RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::return_type, bool> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put_if_absent(const Key& k, Val&& v){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            if constexpr(SharedPtr<Val>){
                return {it->second, false};
            }
            else{
                return {std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second)), false};
            }
        }
    }

    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(current){
        auto it = current->find(k);
        if(it != current->end()){
            if constexpr(SharedPtr<Val>){
                return {it->second, false};
            }
            else{
                return {std::shared_ptr<Val>(current, const_cast<Val*>(&it->second)), false};
            }
        }
    }

    auto new_map = current ? std::make_shared<MapType>(*current) : std::make_shared<MapType>();
    auto [it, inserted] = new_map->emplace(k, std::move(v));

    umap_.store(new_map, std::memory_order_release);

    if constexpr(SharedPtr<Val>){
        return {it->second, true};
    }
    else{
        return {std::shared_ptr<Val>(new_map, &it->second), true};
    }
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::erase(const Key& key){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(!current || current->find(key) == current->end()){
        return;
    }

    auto new_map = std::make_shared<MapType>(*current);
    new_map->erase(key);
    umap_.store(new_map, std::memory_order_release);
}


enum class NodeRole : uint8_t{
    CLIENT       = 1 << 0,
    RELAY        = 1 << 1,
    EXIT         = 1 << 2,
    CLIENT_RELAY = (1 << 0) | (1 << 1)
};


struct NetworkTuple{
    struct ClientView{
        asio::ip::address c_src_addr;
        asio::ip::address c_dest_addr;

        uint16_t c_src_port;
        uint16_t c_dest_port;
    };


    struct ExitView{
        asio::ip::address e_dest_addr;
        asio::ip::address e_client_addr;

        uint16_t e_dest_port;
        uint16_t e_client_port;
    };


    union{
        ClientView client;
        ExitView exit;
    };


    [[nodiscard]] const asio::ip::address& c_src_addr() const{
        return client.c_src_addr;
    }


    [[nodiscard]] const asio::ip::address& c_dest_addr() const{
        return client.c_dest_addr;
    }


    [[nodiscard]] uint16_t c_src_port() const{
        return client.c_src_port;
    }


    [[nodiscard]] uint16_t c_dest_port() const{
        return client.c_dest_port;
    }


    [[nodiscard]] const asio::ip::address& e_dest_addr() const{
        return exit.e_dest_addr;
    }


    [[nodiscard]] const asio::ip::address& e_client_addr() const{
        return exit.e_client_addr;
    }


    [[nodiscard]] uint16_t e_dest_port() const{
        return exit.e_dest_port;
    }


    [[nodiscard]] uint16_t e_client_port() const{
        return exit.e_client_port;
    }


    NetworkTuple() = delete;


    ~NetworkTuple(){
        client.c_src_addr.~address();
        client.c_dest_addr.~address();
    }


    NetworkTuple(const NetworkTuple& other){
        client.c_src_port = other.client.c_src_port;
        client.c_dest_port = other.client.c_dest_port;
        ::new(static_cast<void*>(&client.c_src_addr)) asio::ip::address(other.client.c_src_addr);
        ::new(static_cast<void*>(&client.c_dest_addr)) asio::ip::address(other.client.c_dest_addr);
    }


    NetworkTuple& operator=(const NetworkTuple& other){
        if(this != &other){
            client.c_src_addr = other.client.c_src_addr;
            client.c_dest_addr = other.client.c_dest_addr;
            client.c_src_port = other.client.c_src_port;
            client.c_dest_port = other.client.c_dest_port;
        }
        return *this;
    }


    NetworkTuple(NetworkTuple&& other) noexcept{
        client.c_src_port = other.client.c_src_port;
        client.c_dest_port = other.client.c_dest_port;
        ::new(static_cast<void*>(&client.c_src_addr)) asio::ip::address(std::move(other.client.c_src_addr));
        ::new(static_cast<void*>(&client.c_dest_addr)) asio::ip::address(std::move(other.client.c_dest_addr));
    }


    NetworkTuple& operator=(NetworkTuple&& other) noexcept{
        if(this != &other){
            client.c_src_addr = std::move(other.client.c_src_addr);
            client.c_dest_addr = std::move(other.client.c_dest_addr);
            client.c_src_port = other.client.c_src_port;
            client.c_dest_port = other.client.c_dest_port;
        }
        return *this;
    }


    static NetworkTuple create_client_nt(asio::ip::address src_addr,
                                         asio::ip::address dest_addr,
                                         const uint16_t src_port,
                                         const uint16_t dest_port){
        return {std::move(src_addr), std::move(dest_addr), src_port, dest_port};
    }


    static NetworkTuple create_exit_nt(asio::ip::address client_addr,
                                       asio::ip::address dest_addr,
                                       const uint16_t client_port,
                                       const uint16_t dest_port){
        return {std::move(dest_addr), std::move(client_addr), dest_port, client_port};
    }


    bool operator==(const NetworkTuple& other) const{
        return (client.c_src_addr == other.client.c_src_addr) &&
               (client.c_dest_addr == other.client.c_dest_addr) &&
               (client.c_src_port == other.client.c_src_port) &&
               (client.c_dest_port == other.client.c_dest_port);
    }


    [[nodiscard]] std::string to_string() const{
        return client.c_src_addr.to_string() + ":" + std::to_string(client.c_src_port) + " -> " +
               client.c_dest_addr.to_string() + ":" + std::to_string(client.c_dest_port);
    }

private:
    NetworkTuple(asio::ip::address src_addr, // NOLINT(cppcoreguidelines-pro-type-member-init)
                 asio::ip::address dest_addr,
                 uint16_t src_port,
                 uint16_t dest_port){
        client.c_src_port = src_port;
        client.c_dest_port = dest_port;
        ::new(static_cast<void*>(&client.c_src_addr)) asio::ip::address(std::move(src_addr));
        ::new(static_cast<void*>(&client.c_dest_addr)) asio::ip::address(std::move(dest_addr));
    }
};


template<>
struct std::hash<NetworkTuple>{
    std::size_t operator()(const NetworkTuple& tuple) const noexcept{
        std::size_t seed = 0;

        boost::hash_combine(seed, std::hash<std::string>{}(tuple.c_src_addr().to_string()));
        boost::hash_combine(seed, std::hash<std::string>{}(tuple.c_dest_addr().to_string()));

        boost::hash_combine(seed, std::hash<uint16_t>{}(tuple.c_src_port()));
        boost::hash_combine(seed, std::hash<uint16_t>{}(tuple.c_dest_port()));

        return seed;
    }
};


struct SrcAddrNetworkTuple{
    asio::ip::address e_client_addr;


    bool operator==(const SrcAddrNetworkTuple& other) const{
        return e_client_addr == other.e_client_addr;
    }
};


template<>
struct std::hash<SrcAddrNetworkTuple>{
    std::size_t operator()(const SrcAddrNetworkTuple& tuple) const noexcept{
        std::size_t seed = 0;
        boost::hash_combine(seed, std::hash<std::string>{}(tuple.e_client_addr.to_string()));
        return seed;
    }
};


struct RelayInfo{
    // NOTE: session_id is mutable. it doesn't affect == or the has function
    // we need it to be mutable for establish_connection(const RelayInfo&,...);
    mutable session_id_t session_id; // -1 : not connected, anything else: connected
    asio::ip::udp::endpoint endpoint;
    // todo: relay performance
    mutable std::array<uint8_t, 32> sh_cr{};

    bool operator==(const RelayInfo& other) const{
        return endpoint == other.endpoint;
    }


    std::string to_string() const{
        std::stringstream ss;
        ss << "RelayInfo{";

        if(session_id == static_cast<session_id_t>(-1)){
            ss << "status: not connected";
        }
        else{
            ss << "session_id: " << session_id << ", status: connected";
        }

        ss << ", endpoint: " << endpoint.address().to_string()
            << ":" << endpoint.port() << "}";

        return ss.str();
    }


    bool is_connected() const{
        return session_id != static_cast<session_id_t>(-1);
    }
};


template<>
struct std::hash<RelayInfo>{
    std::size_t operator()(const RelayInfo& info) const noexcept{
        std::size_t seed = 0;

        boost::hash_combine(seed, std::hash<std::string>{}(info.endpoint.address().to_string()));
        boost::hash_combine(seed, std::hash<uint16_t>{}(info.endpoint.port()));

        return seed;
    }
};


template<size_t WindowSeconds = 10>
class Statistics{
public:
    void record_use(uint64_t count = 1){
        auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        auto index = static_cast<size_t>(now_sec % WindowSeconds);
        auto& bucket = buckets_[index];

        int64_t expected_ts = bucket.timestamp_sec.load(std::memory_order_relaxed);
        if(expected_ts != now_sec){
            if(bucket.timestamp_sec.compare_exchange_strong(expected_ts, now_sec, std::memory_order_acq_rel)){
                bucket.count.store(count, std::memory_order_relaxed);
                return;
            }
        }
        bucket.count.fetch_add(count, std::memory_order_relaxed);
    }


    [[nodiscard]] uint64_t get_rate_in_window() const{
        const auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        uint64_t total = 0;
        for(size_t i = 0; i < WindowSeconds; ++i){
            if(int64_t ts = buckets_[i].timestamp_sec.load(std::memory_order_relaxed); now_sec - ts < static_cast<int64_t>(WindowSeconds)){
                total += buckets_[i].count.load(std::memory_order_relaxed);
            }
        }
        return total;
    }


    std::atomic<bool> new_circuit_queued{false};
    std::atomic<bool> dont_create_new_circuit{false};

private:
    struct Bucket{
        std::atomic<int64_t> timestamp_sec{0};
        std::atomic<uint64_t> count{0};
    };


    Bucket buckets_[WindowSeconds];
};


class Client;


struct CircuitInfo{
    circuit_id_t circuit_id;
    std::shared_ptr<std::atomic<sequence_id_t>> sequence_id_ptr;

    std::vector<std::shared_ptr<RelayInfo>> relays; // OPTIMIZE: no vector. use ring buffer (organized by other thread)

    std::array<uint8_t, 32> sh_ce{};
    std::shared_ptr<ReorderBuffer<ArenaSlot<IncomingCell>, sequence_id_t>> reorder_buffer;
    std::optional<NetworkTuple> nt; // nullopt -> default circuit

    std::shared_ptr<Statistics<10>> activity_counter;


    void touch(const std::shared_ptr<Client>& client_ptr) const;
};


struct RelaysInfoGlb{
    using ResponseHandler = std::function<void(boost::system::error_code, std::vector<uint8_t>)>;

    std::unordered_set<RelayInfo> all_relays;
    std::unordered_set<RelayInfo> usable_relays;
    std::mutex registry_mutex_;
    std::unordered_map<txn_id_t, ResponseHandler> pending_requests_;
};


class RandomGen{
public:
    static txn_id_t gen_txn_id(){
        std::uniform_int_distribution<txn_id_t> dist;
        return dist(gen_);
    }


    static sequence_id_t gen_seq_id(){
        std::uniform_int_distribution<sequence_id_t> dist;
        return dist(gen_);
    }


    static session_id_t gen_session_id(){
        std::uniform_int_distribution<session_id_t> dist;
        return dist(gen_);
    }


    static circuit_id_t gen_circuit_id(){
        std::uniform_int_distribution<circuit_id_t> dist;
        return dist(gen_);
    }


    static asio::ip::address_v4 gen_address_v4(){
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
        const uint32_t random_ip_int = dist(gen_);
        return asio::ip::address_v4(random_ip_int);
    }


    static asio::ip::address_v6 gen_address_v6(){
        std::uniform_int_distribution<unsigned short> dist(0, 255);
        asio::ip::address_v6::bytes_type bytes;
        for(auto& byte: bytes){
            byte = static_cast<unsigned char>(dist(gen_));
        }
        return asio::ip::address_v6(bytes);
    }

    static asio::ip::udp::endpoint& choose_exit(std::vector<asio::ip::udp::endpoint> exits){
        std::uniform_int_distribution<std::size_t> dist(0, exits.size() - 1);
        return exits[dist(gen_)];
    }


    inline thread_local static std::mt19937 gen_{std::random_device{}()};
};


inline bool is_relay_diverse(const asio::ip::udp::endpoint& ep, const std::unordered_set<RelayInfo>& existing_relays){
    // FIXME: remove this, just for testing
    return true;

    // fixme: can't we do anything for ipv6 :(
    // just rejecting ipv6
    if(!ep.address().is_v4())
        return false;

    const uint32_t candidate_ip = ep.address().to_v4().to_uint();
    const uint32_t candidate_subnet = candidate_ip & 0xFFFF0000; // /16 mask

    for(const auto& relay: existing_relays){
        if(relay.endpoint.address().is_v4()){
            const uint32_t existing_ip = relay.endpoint.address().to_v4().to_uint();
            if(const uint32_t existing_subnet = existing_ip & 0xFFFF0000; candidate_subnet == existing_subnet){
                return false; // reject nodes sharing the same /16 subnet
            }
        }
    }
    return true;
}