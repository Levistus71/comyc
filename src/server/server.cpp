#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <array>

namespace asio = boost::asio;
using udp = asio::ip::udp;

int main(){
    asio::io_context io_contxt;

    int serv_port = 6969;
    udp::socket socket(io_contxt, udp::endpoint(udp::v4(), serv_port));
    std::cout << "[Server] Listening on port : " << serv_port << std::endl;

    while(true){
        std::array<char, 1024> recv_buf;
        udp::endpoint client;

        // blocked until a packet is received. because this is not TCP, we don't need to open a new socket
        // to talk to the client. use threads if the work load to reply to the client is big.
        size_t bytes_recvd = socket.receive_from(asio::buffer(recv_buf), client);

        std::string message(recv_buf.data(), bytes_recvd);
        std::cout << "[Server] Received " << bytes_recvd << " bytes from " << client << ": \"" << message << "\"\n";

        std::string reply = "RECEIVED DATA: " + std::to_string(bytes_recvd) + " bytes";
        socket.send_to(asio::buffer(reply), client);
    }

    return 0;
}