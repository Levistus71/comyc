#include "src/network/sockets/utun.hpp"

#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>
#include <unistd.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fstream>
#include <sstream>

namespace{
struct in6_rtreq{
    struct in6_addr rtmsg_dst;
    struct in6_addr rtmsg_src;
    struct in6_addr rtmsg_gateway;
    uint32_t rtmsg_type;
    uint16_t rtmsg_dst_len;
    uint16_t rtmsg_src_len;
    uint32_t rtmsg_metric;
    unsigned long rtmsg_info;
    uint32_t rtmsg_flags;
    int rtmsg_ifindex;
};
}

#endif

#include <boost/asio.hpp>
#include <quill/LogMacros.h>


Utun::Utun(const std::string& logger_name){
    logger_ = quill::Frontend::get_logger(logger_name);
    vpn_assigned_ipv4_ = asio::ip::make_address_v4("10.8.0.2");
    dummy_gateway_ipv4_ = asio::ip::make_address_v4("10.8.0.1");
    vpn_assigned_ipv6_ = asio::ip::make_address_v6("fd00::2");
    dummy_gateway_ipv6_ = asio::ip::make_address_v6("fd00::1");
    default_gateway_ipv4_ = asio::ip::make_address_v4("192.168.0.1");
    default_gateway_ipv6_ = asio::ip::make_address_v6("fe80::");
}


Utun::~Utun(){
    stop();
}


void Utun::stop(){
    disable_exit_nat();

    std::lock_guard<std::mutex> lock(route_update_mutex_);

    bool cleared_all = true;
    for(const auto& r: active_routes_){
        if(!modify_route(false, r.dest, r.mask, r.gateway, logger_)){
            cleared_all = false;
        }
    }
    active_routes_.clear();

    if(!cleared_all){
        LOG_CRITICAL(logger_, "[UTUN] Couldn't erase all routes. Cannot guarantee network recovery. Suggest rebooting.");
#if defined(__APPLE__)
        ::system("sudo route -q delete -net 0.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -net 128.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -inet6 -net ::/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -inet6 -net 8000::/1 > /dev/null 2>&1");
#elif defined(__linux__)
        ::system("sudo ip route del 0.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo ip route del 128.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo ip -6 route del ::/1 > /dev/null 2>&1");
        ::system("sudo ip -6 route del 8000::/1 > /dev/null 2>&1");
#endif
    }

    /*
        val.compare_exchange_strong(&expected, desired)
        if(val==expected){
            val = desired;
            return true;
        }
        else{
            expected = val;
            return false;
        }
    */
    if(bool expected = true; running_.compare_exchange_strong(expected, false) == false){
        LOG_ERROR(logger_, "[UTUN] Called stop() more than once.");
        return;
    }

    if(utun_fd_ >= 0){
        if(::close(utun_fd_) < 0){
            LOG_CRITICAL(logger_, "[UTUN] close(utun_fd_) failed. probably data corruption/multithread fail.");
        }
        utun_fd_ = -1;
    }

    LOG_INFO(logger_, "[UTUN] Stopped.");
}


[[nodiscard]] bool Utun::start(const bool hijack_system_traffic,
                               const asio::ip::address_v4& vpn_assigned_v4,
                               const asio::ip::address_v6& vpn_assigned_v6,
                               bool masquerade){
    vpn_assigned_ipv4_ = vpn_assigned_v4;
    vpn_assigned_ipv6_ = vpn_assigned_v6;

    // for configuring utun v6, the vpn_assigned_ipv6_ should be in the same /64 prefix
    {
        auto gw_bytes = vpn_assigned_ipv6_.to_bytes();
        std::memset(gw_bytes.data() + 8, 0, 8);
        gw_bytes[15] = (vpn_assigned_ipv6_.to_bytes()[15] == 1) ? 2 : 1; // lol
        dummy_gateway_ipv6_ = asio::ip::address_v6(gw_bytes);
    }

    {
        auto maybe_gateway = get_default_gateway_v4();
        if(maybe_gateway.has_value()){
            default_gateway_ipv4_ = maybe_gateway.value();
            LOG_INFO(logger_, "[UTUN] default gateway ipv4 found: {}", default_gateway_ipv4_.to_string());
        }
        else
            LOG_INFO(logger_, "[UTUN] default gateway ipv4 found, presuming {}", default_gateway_ipv4_.to_string());
    }
    {
        auto maybe_gateway = get_default_gateway_v6();
        if(maybe_gateway.has_value()){
            default_gateway_ipv6_ = maybe_gateway.value();
            LOG_INFO(logger_, "[UTUN] default gateway ipv6 found: {}", default_gateway_ipv6_.to_string());
        }
        else
            LOG_INFO(logger_, "[UTUN] default gateway ipv4 found, presuming {}", default_gateway_ipv6_.to_string());
    }


    /*
        val.compare_exchange_strong(&expected, desired)
        if(val==expected){
            val = desired;
            return true;
        }
        else{
            expected = val;
            return false;
        }
    */
    if(bool expected = false; running_.compare_exchange_strong(expected, true) == false){
        LOG_ERROR(logger_, "[UTUN] Called start() more than once.");
        stop();
        return false;
    }

    std::unique_lock<std::mutex> lock(route_update_mutex_);

    if(!configure_utun()){
        LOG_ERROR(logger_, "[UTUN] configure_utun() failed.");
        lock.unlock();
        stop();
        return false;
    }

    if(!start_utun()){
        LOG_ERROR(logger_, "[UTUN] start_utun() failed.");
        lock.unlock();
        stop();
        return false;
    }

    if(hijack_system_traffic && !toggle_hijack_on()){
        LOG_ERROR(logger_, "[UTUN] toggle_hijack_on() failed.");
        lock.unlock();
        stop();
        return false;
    }

    if(masquerade){
        RouteConfig client_subnet_route{
            .dest    = asio::ip::make_address("10.0.0.0"),
            .mask    = asio::ip::make_address("255.0.0.0"),
            .gateway = dummy_gateway_ipv4_
        };

        if(!modify_route(true, client_subnet_route.dest, client_subnet_route.mask, client_subnet_route.gateway, logger_)){
            LOG_ERROR(logger_, "[UTUN] Failed to add 10.0.0.0/8 route into utun.");
            lock.unlock();
            stop();
            return false;
        }
        active_routes_.insert(client_subnet_route);
        LOG_INFO(logger_, "[UTUN] Added 10.0.0.0/8 route via {}", dummy_gateway_ipv4_.to_string());

        if(!enable_exit_nat()){
            LOG_ERROR(logger_, "[UTUN] enable_exit_nat() failed.");
            lock.unlock();
            stop();
            return false;
        }
        LOG_INFO(logger_, "[UTUN] utun exit NAT setup complete.");
    }

    return true;
}


int Utun::get_fd() const{
    return utun_fd_;
}


[[nodiscard]] bool Utun::configure_utun(){
#if defined(__APPLE__)
    utun_fd_ = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if(utun_fd_ < 0){
        LOG_ERROR(logger_, "[UTUN] Socket creation failed (try running with sudo).");
        return false;
    }

    // utun_info has the information of the utun. ioctl() puts the id of utun (as the id of the utun
    // chages everytime on reboot) inside utun_info.
    ctl_info utun_info{};
    std::memset(&utun_info, 0, sizeof(utun_info));
    std::strncpy(utun_info.ctl_name, UTUN_CONTROL_NAME, sizeof(utun_info.ctl_name) - 1);

    if(ioctl(utun_fd_, CTLIOCGINFO, &utun_info) < 0){
        LOG_ERROR(logger_, "[UTUN] ioctl(CTLIOCGINFO) failed.");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    // sockaddr_ctl -> struct used to establish contact between a user client and a kernel controller (utun
    // in this case, using the id from utun_info).
    /*
        struct sockaddr_ctl {
            u_char      sc_len;     // depends on size of bundle ID string
            u_char      sc_family;  // AF_SYSTEM
            u_int16_t   ss_sysaddr; // AF_SYS_KERNCONTROL
            u_int32_t   sc_id;      // Controller unique identifier
            u_int32_t   sc_unit;    // Developer private unit number
            u_int32_t   sc_reserved[5];
        };
    */
    sockaddr_ctl addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = utun_info.ctl_id;
    addr.sc_unit = 0; // 0 means let the OS dynamically assign unit (utun0, utun1, etc.)

    if(::connect(utun_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0){
        LOG_ERROR(logger_, "[UTUN] Connect to utun failed.");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    char utun_name[IFNAMSIZ];
    socklen_t utun_name_len = sizeof(utun_name);
    if(::getsockopt(utun_fd_, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utun_name, &utun_name_len) < 0){
        LOG_ERROR(logger_, "[UTUN] Failed to get utun interface name.");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    utun_name_ = std::string(utun_name);
#elif defined(__linux__)
    utun_fd_ = ::open("/dev/net/tun", O_RDWR);
    if(utun_fd_ < 0){
        LOG_ERROR(logger_, "[UTUN] Opening /dev/net/tun failed (try running with sudo).");
        return false;
    }

    ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ - 1);

    if(::ioctl(utun_fd_, TUNSETIFF, reinterpret_cast<void*>(&ifr)) < 0){
        LOG_ERROR(logger_, "[UTUN] TUNSETIFF ioctl failed.");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    utun_name_ = std::string(ifr.ifr_name);
#endif

    LOG_INFO(logger_, "[UTUN] Successfully connected/created interface, name: {}", utun_name_);
    LOG_INFO(logger_, "[UTUN] Configuring IP addresses.");

    if(!configure_utun_v4(vpn_assigned_ipv4_, dummy_gateway_ipv4_)){
        LOG_ERROR(logger_, "[UTUN] Failed to configure interface IPs. ioctl fail?");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    if(!configure_utun_v6(vpn_assigned_ipv6_, dummy_gateway_ipv6_)){
        LOG_ERROR(logger_, "[UTUN] Failed to configure interface IPs. ioctl fail?");
        ::close(utun_fd_);
        utun_fd_ = -1;
        return false;
    }

    LOG_INFO(logger_, "[UTUN] Successfully configured interface: {}", utun_name_);
    return true;
}


[[nodiscard]] bool Utun::configure_utun_v4(const asio::ip::address_v4& local_ip,
                                           const asio::ip::address_v4& remote_ip) const{
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

#if defined(__APPLE__)
    ifaliasreq ifra{};
    std::memset(&ifra, 0, sizeof(ifra));
    std::strncpy(ifra.ifra_name, utun_name_.c_str(), IFNAMSIZ - 1);

    auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifra.ifra_addr);
    addr->sin_family = AF_INET;
    addr->sin_len = sizeof(sockaddr_in);
    inet_pton(AF_INET, local_ip.to_string().c_str(), &addr->sin_addr);

    auto* dst = reinterpret_cast<struct sockaddr_in*>(&ifra.ifra_broadaddr);
    dst->sin_family = AF_INET;
    dst->sin_len = sizeof(sockaddr_in);
    inet_pton(AF_INET, remote_ip.to_string().c_str(), &dst->sin_addr);

    auto* mask = reinterpret_cast<struct sockaddr_in*>(&ifra.ifra_mask);
    mask->sin_family = AF_INET;
    mask->sin_len = sizeof(sockaddr_in);
    inet_pton(AF_INET, "255.255.255.255", &mask->sin_addr);

    const bool res = (::ioctl(sock, SIOCAIFADDR, &ifra) >= 0);
    ::close(sock);
    return res;
#elif defined(__linux__)
    ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, utun_name_.c_str(), IFNAMSIZ - 1);

    auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, local_ip.to_string().c_str(), &addr->sin_addr);
    if(::ioctl(sock, SIOCSIFADDR, &ifr) < 0){
        ::close(sock);
        return false;
    }

    auto* dst = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_dstaddr);
    dst->sin_family = AF_INET;
    inet_pton(AF_INET, remote_ip.to_string().c_str(), &dst->sin_addr);
    ::ioctl(sock, SIOCSIFDSTADDR, &ifr);

    auto* mask = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
    mask->sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.255", &mask->sin_addr);
    ::ioctl(sock, SIOCSIFNETMASK, &ifr);

    ::close(sock);
    return true;
#endif
}


[[nodiscard]] bool Utun::configure_utun_v6(const asio::ip::address_v6& local_ip,
                                           [[maybe_unused]] const asio::ip::address_v6& remote_ip,
                                           const int prefix_len) const{
    const int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

    const unsigned int if_index = if_nametoindex(utun_name_.c_str());
    if(if_index == 0){
        LOG_ERROR(logger_, "[UTUN] if_nametoindex failed for {}", utun_name_);
        ::close(sock);
        return false;
    }

#if defined(__APPLE__)
    in6_aliasreq ifra{};
    std::memset(&ifra, 0, sizeof(ifra));
    std::strncpy(ifra.ifra_name, utun_name_.c_str(), IFNAMSIZ - 1);

    ifra.ifra_addr.sin6_family = AF_INET6;
    ifra.ifra_addr.sin6_len = sizeof(sockaddr_in6);
    ifra.ifra_addr.sin6_scope_id = local_ip.is_link_local() ? if_index : 0;
    inet_pton(AF_INET6, local_ip.to_string().c_str(), &ifra.ifra_addr.sin6_addr);

    // NOTE: Omit ifra_dstaddr for macOS utun v6 aliasing to prevent EINVAL
    // ifra.ifra_dstaddr.sin6_family = AF_INET6;
    // ifra.ifra_dstaddr.sin6_len = sizeof(sockaddr_in6);
    // ifra.ifra_dstaddr.sin6_scope_id = if_index;
    // inet_pton(AF_INET6, remote_ip.to_string().c_str(), &ifra.ifra_dstaddr.sin6_addr);

    ifra.ifra_prefixmask.sin6_family = AF_INET6;
    ifra.ifra_prefixmask.sin6_len = sizeof(sockaddr_in6);
    for(int i = 0; i < prefix_len / 8; i++){
        reinterpret_cast<uint8_t*>(&ifra.ifra_prefixmask.sin6_addr)[i] = 0xFF;
    }
    if(prefix_len % 8){
        reinterpret_cast<uint8_t*>(&ifra.ifra_prefixmask.sin6_addr)[prefix_len / 8] =
            (0xFF << (8 - (prefix_len % 8))) & 0xFF;
    }

    ifra.ifra_lifetime.ia6t_vltime = 0xffffffff; // valid_lifetime: max possible lifetime
    ifra.ifra_lifetime.ia6t_pltime = 0xffffffff; // preferred lifetime: max possible lifetime

    LOG_INFO(logger_, "[UTUN] Configuring IPv6 on {} (idx={}): local={}/{}, remote={}, scope_id={}",
             utun_name_,
             if_index,
             local_ip.to_string(),
             prefix_len,
             remote_ip.to_string(),
             ifra.ifra_addr.sin6_scope_id);

    // const bool res = (::ioctl(sock, SIOCAIFADDR_IN6, &ifra) >= 0);
    const int x = ::ioctl(sock, SIOCAIFADDR_IN6, &ifra);
    if(x < 0){
        LOG_ERROR(logger_, "[UTUN] ioctl() fail. err: {}", errno);
    }
    ::close(sock);
    return x >= 0;
#elif defined(__linux__)
    in6_ifreq ifr6{};
    std::memset(&ifr6, 0, sizeof(ifr6));
    inet_pton(AF_INET6, local_ip.to_string().c_str(), &ifr6.ifr6_addr);
    ifr6.ifr6_prefixlen = prefix_len;
    ifr6.ifr6_ifindex = static_cast<int>(if_index);

    const int res = ::ioctl(sock, SIOCSIFADDR, &ifr6);
    if(res < 0){
        LOG_ERROR(logger_, "[UTUN] ioctl(SIOCSIFADDR) IPv6 fail. err: {}", errno);
    }
    ::close(sock);
    return res >= 0;
#endif
}


[[nodiscard]] bool Utun::start_utun() const{
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

    ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, utun_name_.c_str(), IFNAMSIZ - 1);

    if(::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0){
        ::close(sock);
        return false;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    const bool res = (::ioctl(sock, SIOCSIFFLAGS, &ifr) >= 0);
    ::close(sock);
    return res;
}


[[nodiscard]] bool Utun::toggle_hijack_on(){
    // called from start(), don't need lock.

    const RouteConfig routes[] = {
        {.dest = asio::ip::make_address("0.0.0.0"), .mask = asio::ip::make_address("128.0.0.0"), .gateway = dummy_gateway_ipv4_},
        {.dest = asio::ip::make_address("128.0.0.0"), .mask = asio::ip::make_address("128.0.0.0"), .gateway = dummy_gateway_ipv4_},
        {.dest = asio::ip::make_address("::"), .mask = asio::ip::make_address("8000::"), .gateway = dummy_gateway_ipv6_},
        {.dest = asio::ip::make_address("8000::"), .mask = asio::ip::make_address("8000::"), .gateway = dummy_gateway_ipv6_}
    };

    std::vector<RouteConfig> new_routes;
    for(const auto& t: routes){
        if(modify_route(true, t.dest, t.mask, t.gateway, logger_)){
            new_routes.push_back(t);
        }
        else{
            LOG_ERROR(logger_, "[UTUN] Error while adding routes. Trying rollback.");
            for(auto& [dest, mask, gateway]: new_routes){
                if(!modify_route(false, dest, mask, gateway, logger_)){
                    LOG_CRITICAL(logger_, "[UTUN] Error while rolling back added routes.");
                    return false;
                }
            }
            return false;
        }
    }

    for(auto& t: new_routes)
        active_routes_.insert(t);

    return true;
}


[[nodiscard]] bool Utun::modify_route(const bool enable,
                                      const asio::ip::address& dest,
                                      const asio::ip::address& netmaskv4_prefixv6,
                                      const asio::ip::address& gateway,
                                      quill::Logger* logger){
    if(dest.is_v4() != gateway.is_v4())
        return false;

    if(dest.is_v4()){
        if(!modify_route_v4(enable, dest, netmaskv4_prefixv6, gateway, logger)){
            LOG_INFO(logger, "modify_route_v4 failed: params: enable: {}, dest: {}, netmask: {}, gateway: {}",
                     enable ? "true" : "false", dest.to_string(), netmaskv4_prefixv6.to_string(), gateway.to_string());
            return false;
        }
        return true;
    }
    else{
        if(!modify_route_v6(enable, dest, netmaskv4_prefixv6, gateway, logger)){
            LOG_INFO(logger, "modify_route_v6 failed: params: enable: {}, dest: {}, prefix: {}, gateway: {}",
                     enable ? "true" : "false", dest.to_string(), netmaskv4_prefixv6.to_string(), gateway.to_string());
            return false;
        }
        return true;
    }
}


[[nodiscard]] bool Utun::modify_route_v4(const bool enable,
                                         const asio::ip::address& dest, const asio::ip::address& netmaskv4_prefixv6,
                                         const asio::ip::address& gateway, quill::Logger* logger){
#if defined(__APPLE__)
    const int sock = ::socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if(sock < 0)
        return false;

    struct route_msg_v4{
        rt_msghdr hdr;
        sockaddr_in dst;
        sockaddr_in gateway;
        sockaddr_in mask;
    } msg{};

    const u_char add_delete = (enable) ? RTM_ADD : RTM_DELETE;

    msg.hdr.rtm_msglen = sizeof(msg);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = add_delete;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    msg.hdr.rtm_pid = ::getpid();

    // dest
    msg.dst.sin_family = AF_INET;
    msg.dst.sin_len = sizeof(struct sockaddr_in);
    const auto dst_bytes = dest.to_v4().to_bytes();
    std::memcpy(&msg.dst.sin_addr, dst_bytes.data(), dst_bytes.size());

    // gateway
    msg.gateway.sin_family = AF_INET;
    msg.gateway.sin_len = sizeof(struct sockaddr_in);
    const auto gw_bytes = gateway.to_v4().to_bytes();
    std::memcpy(&msg.gateway.sin_addr, gw_bytes.data(), gw_bytes.size());

    // netmask
    msg.mask.sin_family = AF_INET;
    msg.mask.sin_len = sizeof(struct sockaddr_in);
    const auto mask_bytes = netmaskv4_prefixv6.to_v4().to_bytes();
    std::memcpy(&msg.mask.sin_addr, mask_bytes.data(), mask_bytes.size());

    auto err = ::write(sock, &msg, sizeof(msg));
    if(err < 0){
        LOG_ERROR(logger, "[UTUN] modify_route_v4 write failed: {} (errno={})", std::strerror(errno), errno);
    }
    const bool ret = (err > 0);
    ::close(sock);
    return ret;
#elif defined(__linux__)
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        return false;

    struct rtentry rt{};
    std::memset(&rt, 0, sizeof(rt));

    auto* dst = reinterpret_cast<struct sockaddr_in*>(&rt.rt_dst);
    dst->sin_family = AF_INET;
    const auto dst_bytes = dest.to_v4().to_bytes();
    std::memcpy(&dst->sin_addr, dst_bytes.data(), dst_bytes.size());

    auto* gw = reinterpret_cast<struct sockaddr_in*>(&rt.rt_gateway);
    gw->sin_family = AF_INET;
    const auto gw_bytes = gateway.to_v4().to_bytes();
    std::memcpy(&gw->sin_addr, gw_bytes.data(), gw_bytes.size());

    auto* mask = reinterpret_cast<struct sockaddr_in*>(&rt.rt_genmask);
    mask->sin_family = AF_INET;
    const auto mask_bytes = netmaskv4_prefixv6.to_v4().to_bytes();
    std::memcpy(&mask->sin_addr, mask_bytes.data(), mask_bytes.size());

    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    const unsigned long cmd = enable ? SIOCADDRT : SIOCDELRT;
    const bool ret = (::ioctl(sock, cmd, &rt) >= 0);
    if(ret){
        LOG_ERROR(logger, "[TUN] modify_route_v4 write failed: {} (errno={})", std::strerror(errno), errno);
    }
    ::close(sock);
    return ret;
#endif
}


[[nodiscard]] bool Utun::modify_route_v6(const bool enable,
                                         const asio::ip::address& dest, const asio::ip::address& netmaskv4_prefixv6,
                                         const asio::ip::address& gateway, quill::Logger* logger){
#if defined(__APPLE__)
    const int sock = ::socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if(sock < 0)
        return false;

    struct route_msg_v6{
        rt_msghdr hdr;
        sockaddr_in6 dst;
        sockaddr_in6 gateway;
        sockaddr_in6 mask;
    } msg{};

    const u_char add_delete = (enable) ? RTM_ADD : RTM_DELETE;

    msg.hdr.rtm_msglen = sizeof(msg);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = add_delete;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    msg.hdr.rtm_pid = ::getpid();

    // dest
    msg.dst.sin6_family = AF_INET6;
    msg.dst.sin6_len = sizeof(struct sockaddr_in6);
    const auto dst_bytes = dest.to_v6().to_bytes();
    std::memcpy(&msg.dst.sin6_addr, dst_bytes.data(), dst_bytes.size());

    // gateway
    msg.gateway.sin6_family = AF_INET6;
    msg.gateway.sin6_len = sizeof(struct sockaddr_in6);
    const auto gw_bytes = gateway.to_v6().to_bytes();
    std::memcpy(&msg.gateway.sin6_addr, gw_bytes.data(), gw_bytes.size());

    // netmask
    msg.mask.sin6_family = AF_INET6;
    msg.mask.sin6_len = sizeof(struct sockaddr_in6);
    const auto mask_bytes = netmaskv4_prefixv6.to_v6().to_bytes();
    std::memcpy(&msg.mask.sin6_addr, mask_bytes.data(), mask_bytes.size());

    auto err = ::write(sock, &msg, sizeof(msg));
    if(err < 0){
        LOG_ERROR(logger, "[UTUN] modify_route_v6 write failed: {} (errno={})", std::strerror(errno), errno);
    }
    const bool ret = (err > 0);
    ::close(sock);
    return ret;
#elif defined(__linux__)
    const int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if(sock < 0)
        return false;

    struct in6_rtreq rt6{};
    std::memset(&rt6, 0, sizeof(rt6));

    const auto dst_bytes = dest.to_v6().to_bytes();
    std::memcpy(&rt6.rtmsg_dst, dst_bytes.data(), dst_bytes.size());

    const auto gw_bytes = gateway.to_v6().to_bytes();
    std::memcpy(&rt6.rtmsg_gateway, gw_bytes.data(), gw_bytes.size());

    int prefix_len = 0;
    const auto mask_bytes = netmaskv4_prefixv6.to_v6().to_bytes();
    for(uint8_t byte: mask_bytes){
        while(byte & 0x80){
            prefix_len++;
            byte <<= 1;
        }
    }
    rt6.rtmsg_dst_len = prefix_len;
    rt6.rtmsg_flags = RTF_UP | RTF_GATEWAY;

    const unsigned long cmd = enable ? SIOCADDRT : SIOCDELRT;
    const bool ret = (::ioctl(sock, cmd, &rt6) >= 0);
    if(ret){
        LOG_ERROR(logger, "[TUN] modify_route_v4 write failed: {} (errno={})", std::strerror(errno), errno);
    }
    ::close(sock);
    return ret;
#endif
}


std::optional<asio::ip::address> Utun::get_default_gateway_v4(){
#if defined(__APPLE__)
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t len = 0;

    if(sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0){
        return std::nullopt;
    }

    std::vector<char> buffer(len);
    if(sysctl(mib, 6, buffer.data(), &len, nullptr, 0) < 0){
        return std::nullopt;
    }

    char* ptr = buffer.data();
    char* end = buffer.data() + len;

    while(ptr < end){
        auto* rtm = reinterpret_cast<struct rt_msghdr*>(ptr);
        if(rtm->rtm_version != RTM_VERSION){
            ptr += rtm->rtm_msglen;
            continue;
        }

        auto* sa = reinterpret_cast<struct sockaddr*>(rtm + 1);
        sockaddr* dst = nullptr;
        sockaddr* gw = nullptr;

        for(int i = 0; i < RTAX_MAX; i++){
            if(rtm->rtm_addrs & (1 << i)){
                if(i == RTAX_DST)
                    dst = sa;
                if(i == RTAX_GATEWAY)
                    gw = sa;

                sa = reinterpret_cast<sockaddr*>(
                    reinterpret_cast<char*>(sa) +
                    (sa->sa_len ? ((sa->sa_len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1)) : sizeof(uint32_t))
                );
            }
        }

        if(dst && gw && dst->sa_family == AF_INET && gw->sa_family == AF_INET){
            auto* dst_in = reinterpret_cast<struct sockaddr_in*>(dst);
            auto* gw_in = reinterpret_cast<struct sockaddr_in*>(gw);

            if(dst_in->sin_addr.s_addr == INADDR_ANY && (rtm->rtm_flags & RTF_GATEWAY)){
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(gw_in->sin_addr), ip_str, INET_ADDRSTRLEN);
                return asio::ip::make_address_v4(ip_str);
            }
        }

        ptr += rtm->rtm_msglen;
    }

    return std::nullopt;
#elif defined(__linux__)
    std::ifstream route_file("/proc/net/route");
    if(!route_file.is_open()){
        return std::nullopt;
    }

    std::string line;
    std::getline(route_file, line); // Header line

    while(std::getline(route_file, line)){
        std::istringstream iss(line);
        std::string iface, dest_str, gw_str;
        unsigned int flags = 0;
        if(iss >> iface >> dest_str >> gw_str >> std::hex >> flags){
            if(dest_str == "00000000" && (flags & 0x2 /* RTF_GATEWAY */)){
                auto gw_val = static_cast<uint32_t>(std::stoul(gw_str, nullptr, 16));
                in_addr in{};
                in.s_addr = gw_val;
                char ip_str[INET_ADDRSTRLEN];
                if(inet_ntop(AF_INET, &in, ip_str, INET_ADDRSTRLEN)){
                    return asio::ip::make_address_v4(ip_str);
                }
            }
        }
    }
    return std::nullopt;
#endif
}


std::optional<asio::ip::address_v6> Utun::get_default_gateway_v6(){
#if defined(__APPLE__)
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_DUMP, 0};
    size_t len = 0;

    if(sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0){
        return std::nullopt;
    }

    std::vector<char> buffer(len);
    if(sysctl(mib, 6, buffer.data(), &len, nullptr, 0) < 0){
        return std::nullopt;
    }

    char* ptr = buffer.data();
    char* end = buffer.data() + len;

    while(ptr < end){
        auto* rtm = reinterpret_cast<struct rt_msghdr*>(ptr);
        if(rtm->rtm_version != RTM_VERSION){
            ptr += rtm->rtm_msglen;
            continue;
        }

        auto* sa = reinterpret_cast<struct sockaddr*>(rtm + 1);
        sockaddr* dst = nullptr;
        sockaddr* gw = nullptr;

        for(int i = 0; i < RTAX_MAX; i++){
            if(rtm->rtm_addrs & (1 << i)){
                if(i == RTAX_DST)
                    dst = sa;
                if(i == RTAX_GATEWAY)
                    gw = sa;

                sa = reinterpret_cast<sockaddr*>(
                    reinterpret_cast<char*>(sa) +
                    (sa->sa_len ? ((sa->sa_len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1)) : sizeof(uint32_t))
                );
            }
        }

        if(dst && gw && dst->sa_family == AF_INET6 && gw->sa_family == AF_INET6){
            auto* dst_in6 = reinterpret_cast<struct sockaddr_in6*>(dst);
            auto* gw_in6 = reinterpret_cast<struct sockaddr_in6*>(gw);

            if(IN6_IS_ADDR_UNSPECIFIED(&dst_in6->sin6_addr) && (rtm->rtm_flags & RTF_GATEWAY)){
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(gw_in6->sin6_addr), ip_str, INET6_ADDRSTRLEN);

                auto addr = asio::ip::make_address_v6(ip_str);
                if(gw_in6->sin6_scope_id != 0){
                    addr.scope_id(gw_in6->sin6_scope_id);
                }
                return addr;
            }
        }

        ptr += rtm->rtm_msglen;
    }

    return std::nullopt;
#elif defined(__linux__)
    std::ifstream route_file("/proc/net/ipv6_route");
    if(!route_file.is_open()){
        return std::nullopt;
    }

    std::string line;
    while(std::getline(route_file, line)){
        std::istringstream iss(line);
        std::string dest_str, dest_prefix_str, src_str, src_prefix_str, gw_str, metric_str, ref_str, use_str, flags_str, iface;
        if(iss >> dest_str >> dest_prefix_str >> src_str >> src_prefix_str >> gw_str >> metric_str >> ref_str >> use_str >> flags_str >> iface){
            if(dest_str == "00000000000000000000000000000000" && dest_prefix_str == "00" && gw_str != "00000000000000000000000000000000"){
                in6_addr in6{};
                for(size_t i = 0; i < 16; ++i){
                    std::string byte_str = gw_str.substr(i * 2, 2);
                    in6.s6_addr[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                }
                char ip_str[INET6_ADDRSTRLEN];
                if(inet_ntop(AF_INET6, &in6, ip_str, INET6_ADDRSTRLEN)){
                    return asio::ip::make_address_v6(ip_str);
                }
            }
        }
    }
    return std::nullopt;
#endif
}


namespace{
bool is_local_or_loopback(const asio::ip::address& addr){
    if(addr.is_loopback() || addr.is_multicast() || addr.is_unspecified()){
        return true;
    }

    if(addr.is_v4()){
        const auto bytes = addr.to_v4().to_bytes();
        // 10.0.0.0/8 (Private)
        if(bytes[0] == 10)
            return true;
        // 172.16.0.0/12 (Private)
        if(bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31))
            return true;
        // 192.168.0.0/16 (Private)
        if(bytes[0] == 192 && bytes[1] == 168)
            return true;
        // 100.64.0.0/10 (Carrier-Grade NAT)
        if(bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127))
            return true;
    }
    else if(addr.is_v6()){
        if(addr.to_v6().is_link_local())
            return true;
        const auto bytes = addr.to_v6().to_bytes();
        // fc00::/7 (Unique Local Address - ULA)
        if((bytes[0] & 0xfe) == 0xfc)
            return true;
    }

    return false;
}
}


[[nodiscard]] bool Utun::add_del_route(const bool add,
                                       const asio::ip::address& dest,
                                       const asio::ip::address& netmaskv4_prefixv6,
                                       const asio::ip::address& this_public_ip){
    // todo: uncomment this
    // if(add){
    //     if(is_local_or_loopback(dest) || (!this_public_ip.is_unspecified() && dest == this_public_ip)){
    //         LOG_INFO(logger_, "[UTUN] Skipping route [add] for excluded address: {}", dest.to_string());
    //         return false;
    //     }
    // }

    if(dest == this_public_ip){
        LOG_INFO(logger_, "[UTUN] Skipping route [add] for excluded address: {}", dest.to_string());
        return false;
    }

    const auto gateway = dest.is_v4() ? default_gateway_ipv4_ : default_gateway_ipv6_;

    std::lock_guard<std::mutex> lock(route_update_mutex_);

    bool ip_v4 = dest.is_v4();
    RouteConfig route{
        .dest    = dest,
        .mask    = netmaskv4_prefixv6,
        .gateway = gateway
    };


    if(add){
        if(active_routes_.contains(route))
            return true;

        bool updated = ip_v4
                           ? modify_route_v4(add, dest, netmaskv4_prefixv6, gateway, logger_)
                           : modify_route_v6(add, dest, netmaskv4_prefixv6, gateway, logger_);

        if(updated){
            active_routes_.insert(route);
            LOG_INFO(logger_, "[UTUN] Updated route [add]: {}/{}, gateway: {}",
                     dest.to_string(),
                     netmaskv4_prefixv6.to_string(),
                     gateway.to_string());
            return true;
        }
        else{
            LOG_INFO(logger_, "[UTUN] Failed to update route [add]: {}/{}, gateway: {}",
                     dest.to_string(),
                     netmaskv4_prefixv6.to_string(),
                     gateway.to_string());
            return false;
        }
    }
    else{
        if(!active_routes_.contains(route))
            return true;

        bool updated = ip_v4
                           ? modify_route_v4(add, dest, netmaskv4_prefixv6, gateway, logger_)
                           : modify_route_v6(add, dest, netmaskv4_prefixv6, gateway, logger_);

        if(updated){
            active_routes_.erase(route);
            LOG_INFO(logger_, "[UTUN] Updated route [delete]: {}/{}, gateway: {}",
                     dest.to_string(),
                     netmaskv4_prefixv6.to_string(),
                     gateway.to_string());
            return true;
        }
        else{
            LOG_INFO(logger_, "[UTUN] Failed to update route [delete]: {}/{}, gateway: {}",
                     dest.to_string(),
                     netmaskv4_prefixv6.to_string(),
                     gateway.to_string());
            return false;
        }
    }
}

#include <cerrno>
#include <cstdio>

// Helper for writing sysctl values on Linux
#if defined(__linux__)
namespace {
bool write_proc_sysctl(const std::string& path, const std::string& value) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << value;
    return file.good();
}
} // namespace
#endif

// doesn't act as nat, just forwards packets with the same ip it came with
bool Utun::enable_ip_forwarding() const {
#if defined(__APPLE__)
    int enable = 1;
    if (sysctlbyname("net.inet.ip.forwarding", nullptr, nullptr, &enable, sizeof(enable)) != 0) {
        LOG_ERROR(logger_, "sysctlbyname(net.inet.ip.forwarding) failed: {}", std::strerror(errno));
        return false;
    }
    LOG_INFO(logger_, "ipv4 forwarding enabled.");

    if (sysctlbyname("net.inet6.ip6.forwarding", nullptr, nullptr, &enable, sizeof(enable)) != 0) {
        LOG_ERROR(logger_, "sysctlbyname(net.inet6.ip6.forwarding) failed: {}", std::strerror(errno));
        return false;
    }
    LOG_INFO(logger_, "ipv6 forwarding enabled.");

    return true;

#elif defined(__linux__)
    if (!write_proc_sysctl("/proc/sys/net/ipv4/ip_forward", "1")) {
        LOG_ERROR(logger_, "Failed to enable IPv4 forwarding via /proc/sys/net/ipv4/ip_forward: {}", std::strerror(errno));
        return false;
    }
    LOG_INFO(logger_, "ipv4 forwarding enabled.");

    if (!write_proc_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")) {
        LOG_ERROR(logger_, "Failed to enable IPv6 forwarding via /proc/sys/net/ipv6/conf/all/forwarding: {}", std::strerror(errno));
        return false;
    }
    LOG_INFO(logger_, "ipv6 forwarding enabled.");

    return true;

#else
    LOG_ERROR(logger_, "enable_ip_forwarding is not supported on this platform.");
    return false;
#endif
}

// actual nat
bool Utun::enable_exit_nat(const std::string& external_interface) const {
    if (!enable_ip_forwarding()) {
        return false;
    }

#if defined(__APPLE__)
    std::system("pfctl -e >/dev/null 2>&1");

    const std::string anchor(nat_service_name);

    // 1. Load the actual NAT and filter rules into the sub-anchor
    const std::string anchor_cmd = "pfctl -a " + anchor + " -f -";
    FILE* pipe = popen(anchor_cmd.c_str(), "w");
    if(!pipe){
        LOG_ERROR(logger_, "Failed to open pipe to pfctl: {}", std::strerror(errno));
        return false;
    }

    // Scope NAT to RFC1918 private ranges + CGNAT (100.64.0.0/10) so clients can use any private IP
    // Keep state so return traffic is automatically translated and routed back into utun
    const std::string anchor_rules =
        "table <vpn_private> const { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }\n"
        "nat on " + external_interface + " inet from <vpn_private> to any -> (" + external_interface + ")\n"
        "pass quick on " + utun_name_ + " all keep state\n"
        "pass out quick on " + external_interface + " inet from <vpn_private> to any keep state\n";

    if(fwrite(anchor_rules.data(), 1, anchor_rules.size(), pipe) != anchor_rules.size()){
        LOG_ERROR(logger_, "Failed to write rules to pfctl pipe");
        pclose(pipe);
        return false;
    }

    int rc = pclose(pipe);
    if(rc != 0){
        LOG_ERROR(logger_, "pfctl failed to load anchor '{}' (exit code: {})", anchor, rc);
        return false;
    }

    // 2. Hook our anchor into the main ruleset alongside /etc/pf.conf so macOS actually evaluates it
    const std::string main_cmd = "pfctl -f -";
    FILE* main_pipe = popen(main_cmd.c_str(), "w");
    if(!main_pipe){
        LOG_ERROR(logger_, "Failed to open pipe to pfctl for main ruleset: {}", std::strerror(errno));
        return false;
    }

    const std::string main_rules =
        "scrub-anchor \"com.apple/*\"\n"
        "nat-anchor \"com.apple/*\"\n"
        "nat-anchor \"" + anchor + "\"\n"
        "rdr-anchor \"com.apple/*\"\n"
        "dummynet-anchor \"com.apple/*\"\n"
        "anchor \"com.apple/*\"\n"
        "anchor \"" + anchor + "\"\n"
        "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

    if(fwrite(main_rules.data(), 1, main_rules.size(), main_pipe) != main_rules.size()){
        LOG_ERROR(logger_, "Failed to write main ruleset to pfctl pipe");
        pclose(main_pipe);
        return false;
    }

    rc = pclose(main_pipe);
    if(rc != 0){
        LOG_ERROR(logger_, "pfctl failed to hook anchor '{}' into main ruleset (exit code: {})", anchor, rc);
        return false;
    }

    LOG_INFO(logger_, "Exit NAT enabled on {} for {} (anchor: {})", external_interface, utun_name_, anchor);
    return true;

#elif defined(__linux__)
    // Use dedicated iptables chains named after nat_service_name for clean isolation & teardown
    const std::string chain_nat = std::string(nat_service_name) + "_NAT";
    const std::string chain_fwd = std::string(nat_service_name) + "_FWD";

    // 1. Create custom chains and hook them into POSTROUTING and FORWARD
    std::string setup_cmds =
        "iptables -t nat -N " + chain_nat + " && "
        "iptables -t nat -I POSTROUTING 1 -j " + chain_nat + " && "
        "iptables -N " + chain_fwd + " && "
        "iptables -I FORWARD 1 -j " + chain_fwd;

    if (std::system(setup_cmds.c_str()) != 0) {
        LOG_ERROR(logger_, "Failed to initialize iptables chains ({}, {})", chain_nat, chain_fwd);
        return false;
    }

    // 2. Add MASQUERADE rules for RFC1918 + CGNAT ranges exiting external_interface
    const std::vector<std::string> subnets = {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"
    };

    for (const auto& subnet : subnets) {
        std::string nat_rule = "iptables -t nat -A " + chain_nat +
                               " -s " + subnet + " -o " + external_interface + " -j MASQUERADE";
        if (std::system(nat_rule.c_str()) != 0) {
            LOG_ERROR(logger_, "Failed to apply iptables MASQUERADE rule for {}", subnet);
            return false;
        }
    }

    // 3. Allow bidirectional forwarding between the TUN interface and external interface
    std::string fwd_rules =
        "iptables -A " + chain_fwd + " -i " + utun_name_ + " -o " + external_interface + " -j ACCEPT && "
        "iptables -A " + chain_fwd + " -i " + external_interface + " -o " + utun_name_ +
        " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";

    if (std::system(fwd_rules.c_str()) != 0) {
        LOG_ERROR(logger_, "Failed to apply iptables FORWARD rules for {}", utun_name_);
        return false;
    }

    // Save external_interface in a member variable if needed, or store it for cleanup

    LOG_INFO(logger_, "Exit NAT enabled on {} for {} (chains: {}, {})",
             external_interface, utun_name_, chain_nat, chain_fwd);
    return true;

#else
    (void)external_interface;
    LOG_ERROR(logger_, "enable_exit_nat is not supported on this platform.");
    return false;
#endif
}

bool Utun::disable_exit_nat() {
#if defined(__APPLE__)
    const std::string anchor(nat_service_name);
    const std::string command = "pfctl -a " + anchor + " -F all >/dev/null 2>&1";
    int rc = std::system(command.c_str());
    if(rc != 0){
        LOG_WARNING(logger_, "pfctl failed to flush anchor '{}' (exit code: {})", anchor, rc);
        return false;
    }

    // Reload default /etc/pf.conf to remove the custom anchor hooks
    std::system("pfctl -f /etc/pf.conf >/dev/null 2>&1");

    LOG_INFO(logger_, "Exit NAT disabled (flushed anchor: {})", anchor);
    return true;

#elif defined(__linux__)
    const std::string chain_nat = std::string(nat_service_name) + "_NAT";
    const std::string chain_fwd = std::string(nat_service_name) + "_FWD";

    // Unhook, flush, and delete our custom chains cleanly without disturbing Docker/UFW rules
    std::string cleanup_cmds =
        "iptables -t nat -D POSTROUTING -j " + chain_nat + " >/dev/null 2>&1; "
        "iptables -t nat -F " + chain_nat + " >/dev/null 2>&1; "
        "iptables -t nat -X " + chain_nat + " >/dev/null 2>&1; "
        "iptables -D FORWARD -j " + chain_fwd + " >/dev/null 2>&1; "
        "iptables -F " + chain_fwd + " >/dev/null 2>&1; "
        "iptables -X " + chain_fwd + " >/dev/null 2>&1";

    std::system(cleanup_cmds.c_str());

    LOG_INFO(logger_, "Exit NAT disabled (removed iptables chains: {}, {})", chain_nat, chain_fwd);
    return true;

#else
    LOG_ERROR(logger_, "disable_exit_nat is not supported on this platform.");
    return false;
#endif
}
