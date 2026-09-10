#include <deque>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace asio = boost::asio;


class ChatHandler : public std::enable_shared_from_this<ChatHandler>{
public:
    ChatHandler(asio::io_context& ioc):
        ioc_(ioc),
        write_strand_(ioc_),
        socket_(ioc){}


    void start(){
        read_packet();
    }


    asio::ip::tcp::socket& socket(){
        return socket_;
    }


    void send(std::string msg){
        asio::post(
            write_strand_,
            // * 1. asio::post ALWAYS queues this lambda into the io_context's executor pipeline and returns immediately.
            // * 2. write_strand_ guarantees that even if multiple threads run ioc.run(), this lambda
            // *    will NEVER execute concurrently with any other handler bound to write_strand_.
            // * 3. Capturing `me = shared_from_this()` extends the ChatHandler's lifetime on the heap
            // *    until queue_message() has finished executing.
            [me = shared_from_this(), msg]() mutable{
                me->queue_message(msg);
            }
        );
    }

private:
    asio::io_context& ioc_;
    asio::io_context::strand write_strand_;
    asio::ip::tcp::socket socket_;
    asio::streambuf in_packet_;
    std::deque<std::string> out_packet_que_;


    void read_packet(){
        asio::async_read_until(
            socket_,
            in_packet_,
            '\0',
            [me=shared_from_this()](boost::system::error_code const& ec, size_t bytes_xfer){
                me->process_packet(ec, bytes_xfer);
                // me->read_packet();   // ec is checked in process packet. if some error occurred, (this) would be destroyed in read_packet() after the return

                // this lambda object is in read_packet's stack. but when read_packet() exits, this lambda object would be destroyed. so asio copies this object
                // in it's heap. *me* now is a shared_ptr for *this*. because *me* exists in asio's heap, *this* (ChatHandler) is not nuked in Server.handle_new_connection().
            }
        );
    }


    void process_packet(boost::system::error_code const& ec, size_t bytes_xfer){
        if(ec)
            return;

        // do something with packet

        read_packet();
    }


    void queue_message(std::string msg){
        bool write_in_progress = !out_packet_que_.empty();
        out_packet_que_.push_back(std::move(msg));
        if(!write_in_progress)
            packet_send();
    }


    void packet_send(){
        out_packet_que_.front() += "\0";
        asio::async_write(
            socket_,
            asio::buffer(out_packet_que_.front()),
            asio::bind_executor(
                write_strand_,
                [me = shared_from_this()](boost::system::error_code const& ec, std::size_t /*bytes_transferred*/){
                    me->packet_send_done(ec);
                }
            )
        );
    }


    void packet_send_done(boost::system::error_code const& ec){
        if(ec)
            return;

        out_packet_que_.pop_front();
        if(!out_packet_que_.empty())
            packet_send();
    }
};


class Server{
public:
    Server(size_t num_threads):
        listener_(ioc_),
        thread_count_(num_threads),
        thread_pool_(thread_count_){}


    void start(ssize_t port){
        auto handler = std::make_shared<ChatHandler>(ioc_);

        asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), port);
        listener_.open(endpoint.protocol());
        listener_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        listener_.bind(endpoint);
        listener_.listen();

        listener_.async_accept(
            handler->socket(),
            [=](auto ec){
                handle_new_connection(handler, ec);
            }
        );

        for(int i = 0; i < thread_count_; i++){
            thread_pool_.emplace_back(
                [=]{
                    ioc_.run();
                }
            );
        }
    }

private:
    asio::io_context ioc_;
    size_t thread_count_;
    std::vector<std::thread> thread_pool_;
    asio::ip::tcp::acceptor listener_;


    void handle_new_connection(std::shared_ptr<ChatHandler> handler, boost::system::error_code const& ec){
        if(ec)
            return;

        handler->start();

        std::shared_ptr<ChatHandler> new_handler = std::make_shared<ChatHandler>(ioc_);
        listener_.async_accept(
            new_handler->socket(),
            [=](auto new_ec){
                handle_new_connection(new_handler, new_ec);
            }
        );

        // you'd think handler is being nuked here. look at ChatHandler.read_packet() notes
    }
};


int main(){
    Server server(2);
    std::cout << "Started server on port 8888." << std::endl;
    server.start(8888);

    return 0;
}
