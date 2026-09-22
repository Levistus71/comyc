#include "src/network/sockets/utun.hpp"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet6/nd6.h>

#include <string>

#include <boost/asio.hpp>

#include <quill/LogMacros.h>


Utun::Utun(){
    logger_ = quill::Frontend::get_logger("client_logger");
}


Utun::~Utun(){
    stop();
}


void Utun::stop(){
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

    bool cleared_all = true;
    for(const auto& r: active_routes_){
        if(!modify_route(false, r.dest, r.mask, r.gateway)){
            cleared_all = false;
        }
    }
    active_routes_.clear();

    if(utun_fd_ >= 0){
        ::close(utun_fd_);
        utun_fd_ = -1;
    }

    if(!cleared_all){
        LOG_CRITICAL(logger_, "[UTUN] Couldn't erase all routes. Cannot guarantee network recovery.");
        ::system("sudo route -q delete -net 0.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -net 128.0.0.0/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -inet6 -net ::/1 > /dev/null 2>&1");
        ::system("sudo route -q delete -inet6 -net 8000::/1 > /dev/null 2>&1");
        return;
    }

    LOG_INFO(logger_, "[UTUN] Stopped successfully.");
}


[[nodiscard]] bool Utun::start(){
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

    if(!configure_utun()){
        LOG_ERROR(logger_, "[UTUN] configure_utun() failed.");
        stop();
        return false;
    }

    if(!start_utun()){
        LOG_ERROR(logger_, "[UTUN] start_utun() failed.");
        stop();
        return false;
    }

    if(!toggle_hijack_on()){
        LOG_ERROR(logger_, "[UTUN] toggle_hijack_on() failed.");
        stop();
        return false;
    }

    LOG_INFO(logger_, "[UTUN] Started successfully.");
    return true;
}


inline int Utun::get_fd() const{
    return utun_fd_;
}


[[nodiscard]] bool Utun::configure_utun(){
    utun_fd_ = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if(utun_fd_ < 0){
        LOG_ERROR(logger_, "[UTUN] Socket creation failed (try running with sudo).");
        return false;
    }

    // utun_info has the information of the utun. ioctl() puts the id of utun (as the id of the utun
    // chages everytime on reboot) inside utun_info.
    ctl_info utun_info{};
    std::memset(&utun_info, 0, sizeof(utun_info));
    std::strncpy(utun_info.ctl_name, UTUN_CONTROL_NAME, sizeof(utun_info.ctl_name));

    if(ioctl(utun_fd_, CTLIOCGINFO, &utun_info) < 0){
        LOG_ERROR(logger_, "[UTUN] ioctl() failed.");
        ::close(utun_fd_);
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
        return false;
    }

    char utun_name[IFNAMSIZ];
    socklen_t utun_name_len = sizeof(utun_name);
    if(::getsockopt(utun_fd_, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utun_name, &utun_name_len) < 0){
        LOG_ERROR(logger_, "[UTUN] Failed to get utun interface name.");
        ::close(utun_fd_);
        return false;
    }

    LOG_INFO(logger_, "[UTUN] Successfully connected to utun, name: {}", utun_name);
    LOG_INFO(logger_, "[UTUN] Trying to hijack system traffic.");

    if(!configure_utun_v4(asio::ip::make_address_v4("10.8.0.2"), asio::ip::make_address_v4("10.8.0.1"))){
        LOG_ERROR(logger_, "[UTUN] Failed to configure interface IPs. ioctl fail?");
        ::close(utun_fd_);
        return false;
    }

    if(!configure_utun_v6(asio::ip::make_address_v6("10.8.0.2"), asio::ip::make_address_v6("10.8.0.1"))){
        LOG_ERROR(logger_, "[UTUN] Failed to configure interface IPs. ioctl fail?");
        ::close(utun_fd_);
        return false;
    }

    utun_name_ = std::string(utun_name);
    const std::string setup_cmd =
        "ifconfig " + utun_name_ + " 10.8.0.2 10.8.0.1 up && "
        "route add -net 0.0.0.0/1 10.8.0.1 > /dev/null 2>&1 && "
        "route add -net 128.0.0.0/1 10.8.0.1 > /dev/null 2>&1";

    if(std::system(setup_cmd.c_str()) != 0){
        LOG_ERROR(logger_, "[UTUN] Failed to hijack system traffic.");
        ::close(utun_fd_);
        return false;
    }

    LOG_INFO(logger_, "[UTUN] Successfully hijacked system traffic, routed through: {}", utun_name_);
    return true;
}


[[nodiscard]] bool Utun::configure_utun_v4(const asio::ip::address_v4& local_ip,
                                           const asio::ip::address_v4& remote_ip) const{
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

    ifaliasreq ifra{};
    std::memset(&ifra, 0, sizeof(ifra));
    std::strncpy(ifra.ifra_name, utun_name_.c_str(), IFNAMSIZ);

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
}


[[nodiscard]] bool Utun::configure_utun_v6(const asio::ip::address_v6& local_ip,
                                           const asio::ip::address_v6& remote_ip,
                                           const int prefix_len) const{
    const int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

    in6_aliasreq ifra{};
    std::memset(&ifra, 0, sizeof(ifra));
    std::strncpy(ifra.ifra_name, utun_name_.c_str(), IFNAMSIZ);

    ifra.ifra_addr.sin6_family = AF_INET6;
    ifra.ifra_addr.sin6_len = sizeof(sockaddr_in6);
    inet_pton(AF_INET6, local_ip.to_string().c_str(), &ifra.ifra_addr.sin6_addr);

    ifra.ifra_dstaddr.sin6_family = AF_INET6;
    ifra.ifra_dstaddr.sin6_len = sizeof(sockaddr_in6);
    inet_pton(AF_INET6, remote_ip.to_string().c_str(), &ifra.ifra_dstaddr.sin6_addr);

    ifra.ifra_prefixmask.sin6_family = AF_INET6;
    ifra.ifra_prefixmask.sin6_len = sizeof(sockaddr_in6);
    for(int i = 0; i < prefix_len / 8; i++){
        reinterpret_cast<uint8_t*>(&ifra.ifra_prefixmask.sin6_addr)[i] = 0xFF;
    }
    if(prefix_len % 8){
        reinterpret_cast<uint8_t*>(&ifra.ifra_prefixmask.sin6_addr)[prefix_len / 8] =
            (0xFF << (8 - (prefix_len % 8))) & 0xFF;
    }

    ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
    ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

    const bool res = (::ioctl(sock, SIOCAIFADDR_IN6, &ifra) >= 0);
    ::close(sock);
    return res;
}


[[nodiscard]] bool Utun::start_utun() const{
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        return false;
    }

    ifreq ifr{};
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, utun_name_.c_str(), IFNAMSIZ);

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
    const RouteConfig routes[] = {
        {.dest = asio::ip::make_address("0.0.0.0"), .mask = asio::ip::make_address("128.0.0.0"), .gateway = dummy_gateway_ipv4_},
        {.dest = asio::ip::make_address("128.0.0.0"), .mask = asio::ip::make_address("128.0.0.0"), .gateway = dummy_gateway_ipv4_},
        {.dest = asio::ip::make_address("::"), .mask = asio::ip::make_address("8000::"), .gateway = dummy_gateway_ipv6_},
        {.dest = asio::ip::make_address("8000::"), .mask = asio::ip::make_address("8000::"), .gateway = dummy_gateway_ipv6_}
    };

    std::vector<RouteConfig> new_routes;
    for(const auto& t: routes){
        if(modify_route(true, t.dest, t.mask, t.gateway)){
            new_routes.push_back(t);
        }
        else{
            LOG_ERROR(logger_, "[UTUN] Error while adding routes. Trying rollback.");
            for(auto& [dest, mask, gateway]: new_routes){
                if(!modify_route(false, dest, gateway, mask)){
                    LOG_CRITICAL(logger_, "[UTUN] Error while rolling back added routes.");
                    return false;
                }
            }
            return false;
        }
    }

    active_routes_ = new_routes;

    return true;
}


[[nodiscard]] bool Utun::modify_route(const bool enable,
                                      const asio::ip::address& dest,
                                      const asio::ip::address& netmaskv4_prefixv6,
                                      const asio::ip::address& gateway){
    if(dest.is_v4() != gateway.is_v4())
        return false;

    if(dest.is_v4()){
        return modify_route_v4(enable, dest, netmaskv4_prefixv6, gateway);
    }
    else{
        return modify_route_v6(enable, dest, netmaskv4_prefixv6, gateway);
    }
}


[[nodiscard]] bool Utun::modify_route_v4(const bool enable, const asio::ip::address& dest, const asio::ip::address& netmaskv4_prefixv6, const asio::ip::address& gateway){
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

    const bool ret = (::write(sock, &msg, sizeof(msg)) > 0);
    ::close(sock);
    return ret;
}


[[nodiscard]] bool Utun::modify_route_v6(const bool enable, const asio::ip::address& dest, const asio::ip::address& netmaskv4_prefixv6, const asio::ip::address& gateway){
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

    const bool ret = (::write(sock, &msg, sizeof(msg)) > 0);
    ::close(sock);
    return ret;
}
