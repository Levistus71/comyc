#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <array>

namespace asio = boost::asio;
using udp = asio::ip::udp;

int main(){
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