#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>

#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <array>

namespace asio = boost::asio;
using udp = asio::ip::udp;


// MACOS
// sudo route -n flush

struct UtunContxt{
    int fd;
    std::string utun_name;
    std::string server_ip;
};


int connect_utun(const std::string& server_ip){
    /*
     socket -> endpoint for network connections. args: (domain, type, protocol)
            domain -> protocol family (AF_NET:IPv4, AF_INET6:IPv6). PF_SYSTEM: system-level communications
            type -> SOCK_STREAM: 2 way connection (use for TCP), SOCK_DGRAM: 1 way connection (use for UDP)
            protocol -> TCP/UDP. SYSPROTO_CONTROL: socket must connect directly to a registered Kernel Control

            why we use SOCK_DGRAM? SOCK_STREAM treats the incoming data as a continuous stream. if the kernel
            receives 2 packets from different apps, it probably combines both those packets into one single stream
            using SOCK_STREAM. SOCK_DGRAM treats it as 2 different packets.
     
     returns a file descriptor
    */
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("[Client] Socket creation failed (run with sudo)");
        return -1;
    }

    // utun_info has the information of the utun. ioctl() puts the id of utun (as the id of the utun
    // chages everytime on reboot) inside utun_info.
    struct ctl_info utun_info;
    std::memset(&utun_info, 0, sizeof(utun_info));
    std::strncpy(utun_info.ctl_name, UTUN_CONTROL_NAME, sizeof(utun_info.ctl_name));

    if (ioctl(fd, CTLIOCGINFO, &utun_info) < 0) {
        perror("[Client] ioctl() failed.");
        close(fd);
        return -1;
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
    struct sockaddr_ctl addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = utun_info.ctl_id;
    addr.sc_unit = 0; // 0 means let the OS dynamically assign unit (utun0, utun1, etc.)

    if(connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0){
        perror("[Client] Connect to utun failed.");
        close(fd);
        return -1;
    }

    char utun_name[IFNAMSIZ];
    socklen_t utun_name_len = sizeof(utun_name);
    if(getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utun_name, &utun_name_len) < 0){
        perror("[Client] Failed to get utun interface name.");
        close(fd);
        return -1;
    }

    std::cout << "[Client] Successfully connected to utun, name: " << utun_name << std::endl;
    std::cout << "[Client] Trying to hijack system traffic." << std::endl;
    
    std::string utun_name_str(utun_name);
    std::string setup_cmd = 
        "ifconfig " + utun_name_str + " 10.8.0.2 10.8.0.1 up && "
        "route add -host " + server_ip + " $(route -n get default | awk '/gateway:/ {print $2}') > /dev/null 2>&1 && "
        "route add -net 0.0.0.0/1 10.8.0.1 > /dev/null 2>&1 && "
        "route add -net 128.0.0.0/1 10.8.0.1 > /dev/null 2>&1";

    if(std::system(setup_cmd.c_str()) != 0){
        std::cerr << "[Client] Failed to hijack system traffic.\n";
        close(fd);
        return -1;
    }

    std::cout << "[Client] Successfully hijacked system traffic, routed through: " << utun_name_str << std::endl;
    return fd;
}


void simple_udp_client(){
    asio::io_context io_contxt;

    udp::resolver resolver(io_contxt);
    int serv_port = 6969;
    udp::endpoint serv_endpoint = *resolver.resolve(udp::v4(), "127.0.0.1", std::to_string(serv_port)).begin();

    udp::socket socket(io_contxt);
    socket.open(udp::v4());

    std::cout << "[Client] Connected to server." << std::endl;
    std::cout << "Type a message" << std::endl;

    std::string input;
    while(true){
        std::cout << "> ";
        std::getline(std::cin, input);

        if(input.empty())
            continue;

        socket.send_to(asio::buffer(input), serv_endpoint);

        std::array<char, 1024> recv_buf;
        udp::endpoint sender_endpoint;
        size_t bytes_recvd = socket.receive_from(asio::buffer(recv_buf), sender_endpoint);

        std::string ack(recv_buf.data(), bytes_recvd);
        std::cout << "[Client] Server replied: \"" << ack << "\"\n";
    }
}


int utun_test(){
    int utun_fd = connect_utun("8.8.8.8"); // TODO: REPLACE, temporarily google
    if(utun_fd==-1)
        return -1;

    uint8_t packet_buffer[1500];
    std::cout << "[Client] Listening for raw packets on utun." << std::endl;

    while(true){
        // macOS utun prepends a 4-byte address family header to each packet
        ssize_t bytes_read = read(utun_fd, packet_buffer, sizeof(packet_buffer));
        if (bytes_read > 0) {
            std::cout << "[Client] Captured raw IP packet: " << bytes_read << " bytes\n";
            // packet_buffer + 4 now contains the raw IPv4/IPv6 header + payload

            // * our routing logic from here.
        }
    }

    close(utun_fd);
    return 0;
}

int main(){
    // simple_udp_client();
    utun_test();
    return 0;    
}