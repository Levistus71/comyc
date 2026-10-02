#pragma once

#include <atomic>
#include <string>
#include <unordered_set>

#include <quill/Frontend.h>

#include <boost/asio.hpp>

/*
 * Client:
 *      1. The browser opens a socket to Google
 *      2. The OS kernel looks up the route for Google's IP,
 *          matches the hijack rule pointing to dummy_gateway_ip, and determines the egress interface is utun
 *      3. The kernel checks the utun interface for its assigned address and stamps vpn_assigned_ip
 *          as the Source IP on the packet header. All the ip packets on in the file descriptor have vpn_assigned_ip on it.
 *      4. We read it from the utun and send client_ip + (vpn_assigned_ip payload) to relays
 *      ... exit processing
 *      5. we get back packet with google's ip and vpn_assigned_ip back
 *      6. hand this packet to os, hands packet back to browser.
 */


namespace asio = boost::asio;


struct RouteConfig{
    asio::ip::address dest;
    asio::ip::address mask;
    asio::ip::address gateway;


    bool operator==(const RouteConfig& other) const{
        return dest == other.dest &&
               mask == other.mask &&
               gateway == other.gateway;
    }
};


namespace std{
template<>
struct hash<RouteConfig>{
    std::size_t operator()(const RouteConfig& config) const noexcept{
        std::size_t h1 = std::hash<std::string>{}(config.dest.to_string());
        std::size_t h2 = std::hash<std::string>{}(config.mask.to_string());
        std::size_t h3 = std::hash<std::string>{}(config.gateway.to_string());

        std::size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);

        return seed;
    }
};
}


class Utun{
public:
    Utun(const std::string& logger_name);


    ~Utun();


    Utun(const Utun&) = delete;


    Utun& operator=(const Utun&) = delete;


    [[nodiscard]] bool start(bool hijack_system_traffic);


    void stop();


    [[nodiscard]] int get_fd() const;


    /*
     * binding the socket to en0 doesn't work. os: "No route to host" (tries to route again instead of directly sending).
     */
    // [[nodiscard]] bool bind_to_en0(asio::ip::udp::socket& socket, const std::string& interface_name, boost::system::error_code& ec) const;


    [[nodiscard]] bool add_del_route(bool add,
                                     const asio::ip::address& dest,
                                     const asio::ip::address& netmaskv4_prefixv6,
                                     const asio::ip::address& gateway);

private:
    int utun_fd_ = -1;
    std::atomic<bool> running_ = false;
    std::string utun_name_;

    quill::Logger* logger_{nullptr};

    asio::ip::address_v4 vpn_assigned_ipv4_;
    asio::ip::address_v4 dummy_gateway_ipv4_;
    asio::ip::address_v6 vpn_assigned_ipv6_;
    asio::ip::address_v6 dummy_gateway_ipv6_;

    std::mutex route_update_mutex_;                 // locks are fine, route updates happen occasionally (not frequent).
    std::unordered_set<RouteConfig> active_routes_; // accessed only in start(), stop(), ~Utun() and modify_route(). all use lock.


    [[nodiscard]] static bool modify_route(bool enable,
                                           const asio::ip::address& dest,
                                           const asio::ip::address& netmaskv4_prefixv6,
                                           const asio::ip::address& gateway);


    [[nodiscard]] bool configure_utun();


    [[nodiscard]] bool configure_utun_v4(const asio::ip::address_v4& local_ip,
                                         const asio::ip::address_v4& remote_ip) const;


    [[nodiscard]] bool configure_utun_v6(const asio::ip::address_v6& local_ip,
                                         const asio::ip::address_v6& remote_ip,
                                         int prefix_len = 64) const;


    // "interface up" kinda command
    [[nodiscard]] bool start_utun() const;


    // route add -net 0.0.0.0/1 -interface utun0 && route add -net 128.0.0.0/1 -interface utun0 kinda command
    [[nodiscard]] bool toggle_hijack_on();


    [[nodiscard]] static bool modify_route_v4(bool enable,
                                              const asio::ip::address& dest,
                                              const asio::ip::address& netmaskv4_prefixv6,
                                              const asio::ip::address& gateway);


    [[nodiscard]] static bool modify_route_v6(bool enable,
                                              const asio::ip::address& dest,
                                              const asio::ip::address& netmaskv4_prefixv6,
                                              const asio::ip::address& gateway);
};


/*
    asio::ip::address_v4 dummy_local_ipv4 = asio::ip::make_address_v4("10.8.0.2"),
    asio::ip::address_v4 dummy_gateway_ipv4 = asio::ip::make_address_v4("10.8.0.1"),
    asio::ip::address_v6 dummy_local_ipv6 = asio::ip::make_address_v6(""),
    asio::ip::address_v6 dummy_gateway_ipv6 = asio::ip::make_address_v6("fd00::1")
 */
