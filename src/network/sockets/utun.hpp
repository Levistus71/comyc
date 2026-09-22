#pragma once

#include <atomic>
#include <string>
#include <quill/Frontend.h>

#include <boost/asio.hpp>

namespace asio = boost::asio;


class Utun{
public:
    Utun();


    ~Utun();


    Utun(const Utun&) = delete;


    Utun& operator=(const Utun&) = delete;


    [[nodiscard]] bool start();


    void stop();


    [[nodiscard]] inline int get_fd() const;

private:
    struct RouteConfig{
        asio::ip::address dest;
        asio::ip::address mask;
        asio::ip::address gateway;
    };


    int utun_fd_ = -1;
    std::atomic<bool> running_ = false;
    std::string utun_name_;
    quill::Logger* logger_{nullptr};
    std::vector<RouteConfig> active_routes_;
    asio::ip::address_v4 dummy_local_ipv4_;
    asio::ip::address_v4 dummy_gateway_ipv4_;
    asio::ip::address_v6 dummy_local_ipv6_;
    asio::ip::address_v4 dummy_gateway_ipv6_;


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
