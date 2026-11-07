#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <csignal>
#include <sys/select.h>

#include "../network/sockets/udp_sock.hpp"
#include "../network/comms/ice_comms.hpp"
#include "stun.hpp"
#include "turn.hpp"

using namespace comyc::network::sockets;
using namespace comyc::network::comms;
using namespace comyc::ice_server;

// flag to control graceful server shutdown
static volatile bool g_running = true;

void signal_handler(int signum){
    (void)signum;
    g_running = false;
}

int main(int argc, char* argv[]){
    uint16_t port = 3478; // standard STUN/TURN default port
    std::string public_ip = "127.0.0.1";

    if(argc>1) port = static_cast<uint16_t>(std::atoi(argv[1]));
    if(argc>2) public_ip = argv[2];

    // SIGINT/SIGTERM handlers for graceful exit
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // initialise main listening UDP socket
    UdpSocket server_sock;
    if(!server_sock.open() || !server_sock.bind(port)){
        std::cerr << "[ICE Server] Error: Failed to bind to port " << port << std::endl;
        return 1;
    }

    std::cout << "[ICE Server] Running on " << public_ip << ":" << port << std::endl;

    StunServer stun_engine;
    TurnServer turn_engine(public_ip);

    constexpr size_t BUFFER_SIZE = 2048;
    std::vector<uint8_t> buffer(BUFFER_SIZE);

    auto last_purge_time = std::chrono::steady_clock::now();

    // main non-blocking I/O event loop
    while(g_running){
        fd_set readfds;
        FD_ZERO(&readfds);

        int max_fd = server_sock.get_fd();
        FD_SET(max_fd, &readfds);

        // timeout struct for select (100ms)
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int activity = ::select(max_fd+1, &readfds, nullptr, nullptr, &timeout);

        if(activity<0 && errno!=EINTR){
            std::cerr << "[ICE Server] Select erro occurred." << std::endl;
            break;
        }

        // process incoming packet on main socket
        if(activity>0 && FD_ISSET(server_sock.get_fd(), &readfds)){
            Endpoint sender_ep;
            ssize_t bytes_read = server_sock.recv_from(buffer.data(), buffer.size(), sender_ep);

            if(bytes_read>0){
                std::vector<uint8_t> response_payload;
                Endpoint forward_dest;
                std::vector<uint8_t> forward_payload;

                // attempt STUN processing (reflection)
                if(stun_engine.process_packet(buffer.data(), static_cast<size_t>(bytes_read), sender_ep, response_payload)){
                    server_sock.send_to(response_payload, sender_ep);
                }
                // attempt TURN processing (allocation/relay/send indications)
                else if(turn_engine.process_packet(buffer.data(), static_cast<size_t>(bytes_read), sender_ep,
                                                   response_payload, forward_dest, forward_payload)){
                    // send TURN control response back to client (if generated)
                    if(!response_payload.empty()){
                        server_sock.send_to(response_payload, sender_ep);
                    }
                    // forward raw payload dat to peer (if processing a SEND_INIDCATION)
                    if(!forward_payload.empty() && forward_dest.port!=0){
                        server_sock.send_to(forward_payload, forward_dest);
                    }
                }
            }
        }
        // periodic maintenance: purge expired TURN allocations every 5s
        auto now = std::chrono::steady_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(now-last_purge_time).count() >= 5){
            turn_engine.purge_expired_allocations();
            last_purge_time = now;
        }
    }

    std::cout << "\n[ICE Server] Shutting down cleanly..." << std::endl;
    server_sock.close_socket();
    return 0;
}