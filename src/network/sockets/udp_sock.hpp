#ifndef COMYC_UDP_SOCK_HPP
#define COMYC_UDP_SOCK_HPP

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <system_error>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

namespace comyc::network::sockets{

struct Endpoint{
    std::string ip;
    uint16_t port{0};

    // Helper to populate a POSIX sockaddr_in structure
    // Used right before sending to network(sendto())
    sockaddr_in to_sockaddr() const{
        sockaddr_in addr{};
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET; // IPv4 addr family
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        return addr;
    }

    // Helper to extract IP and port from a socketadd_in
    // Used right after receiving from network(recvfrom())
    static Endpoint from_sockaddr(const sockaddr_in& addr){
        Endpoint ep;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        ep.ip = std::string(ip_str);
        ep.port = ntohs(addr.sin_port);
        return ep;
    }
};

class UpdSocket{
private:
    int sockfd_{-1}; // Initialised to -1

public:
    UpdSocket() = default;

    ~UpdSocket(){
        close_socket();
    }

    // Prevent copying to manage socket descriptor cleanly
    UpdSocket(const UpdSocket&) = delete;
    UpdSocket& operator=(const UpdSocket&) = delete;

    // Allow move semantics
    UpdSocket& operator=(UpdSocket&& other) noexcept{
        if(this != &other){
            close_socket();
            sockfd_ = other.sockfd_;
            other.sockfd_ = -1;
        }
        return *this;
    }

    // Initialise UDP socket, configure SO_REUSEADDR/PORT, and set non-blocking I/O
    bool open(){
        sockfd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if(sockfd_ < 0){
            return false;
        }

        int opt = 1;
        ::setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        ::setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

        return set_non_blocking(true);
    }

    // Bind socket to a local port (ip = "0.0.0.0" to bind all interfaces)
    bool bind(uint16_t port, const std::string& ip = "0.0.0.0"){
        if(sockfd_ < 0 && !open()){
            return false;
        }

        Endpoint ep{ip, port};
        sockaddr_in addr = ep.to_sockaddr();

        if(::bind(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0){
            return false;
        }
        return true;
    }

    // Toggle O_NONBLOCK flag on the socket file descriptor
    // Calling recv_from() on an empty socket returns immediately 
    // with -1 (EWOULDBLOCK/EAGAIN) instead of freezing the server loop 
    // while waiting for network traffic 
    bool set_non_blocking(bool enable){
        if(sockfd_ < 0) return false;
        int flags = ::fcntl(sockfd_, F_GETFL, 0);
        if(flags < 0) return false;
        flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        return ::fcntl(sockfd_, F_SETFL, flags) >= 0;
    }

    // Send a datagram to a target endpoint
    ssize_t send_to(const uint8_t* data, size_t length, const Endpoint& dest){
        if(sockfd_ < 0) return -1;
        sockaddr_in addr = dest.to_sockaddr();
        return ::sendto(sockfd_, data, length, 0, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    }

    // Convenient vector wrapper for send_to
    ssize_t send_to(const std::vector<uint8_t>& buffer, const Endpoint& dest){
        return send_to(buffer.data(), buffer.size(), dest);
    }

    // Receive a datagram; returns bytes read and populates sender_ep
    // Returns -1 if no data is available (EWOULDBLOCK/EAGAIN in non-blocking mode)
    ssize_t recv_from(uint8_t* buffer, size_t max_length, Endpoint& sender_ep){
        if(sockfd_ < 0) return -1;

        sockaddr_in addr{};
        socklen_t addr_len = sizeof(addr);

        ssize_t bytes_read = ::recvfrom(sockfd_, buffer, max_length, 0, reinterpret_cast<sockaddr*>(&addr), &addr_len);

        if(bytes_read > 0){
            sender_ep = Endpoint::from_sockaddr(addr);
        }
        return bytes_read;
    } 

    // Get assigned local port (useful bound to port 0 for dynamic allocation)
    uint16_t get_local_port() const{
        if(sockfd_ < 0) return 0;
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        if(::getsockname(sockfd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0){
            return ntohs(addr.sin_port);
        }
        return 0;
    }

    void close_socket(){
        if(sockfd_ >= 0){
            ::close(sockfd_);
            sockfd_ = -1;
        }
    }

    int get_fd() const{ return sockfd_; }
    bool is_valid() const{ return sockfd_ >= 0; }
};

} // namespace comyc::network::sockets

#endif // COMYC_UDP_SOCK_HPP