#pragma once

#include "src/node/cli.hpp"
#include <boost/asio.hpp>
#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <chrono>
#include <sstream>


#include <quill/Logger.h>


namespace telemetry{
namespace asio = boost::asio;


class DemoReporter{
public:
    static DemoReporter& instance(){
        static DemoReporter s_instance;
        return s_instance;
    }


    [[nodiscard]] bool init(asio::io_context& ioc, const std::shared_ptr<asio::ip::udp::socket>& socket,
                            const std::shared_ptr<cli::CliOptions>& options, quill::Logger* logger){
        logger_ = logger;

        if(!options || !options->demo_mode){
            enabled_ = false;
            return false;
        }

        enabled_ = true;
        role_str_ = std::string(cli::CliParser::role_to_string(options->role));
        node_id_ = role_str_ + "-" + std::to_string(options->listen_port ? options->listen_port : (reinterpret_cast<uintptr_t>(this) % 10000));
        listen_port_ = options->listen_port;

        boost::system::error_code ec;
        auto addr = asio::ip::make_address(options->demo_host_ip, ec);
        if(ec){
            log_error("couldn't make address with ip: {}", options->demo_host_ip);
            return false;
        }
        target_endpoint_ = asio::ip::udp::endpoint(addr, options->demo_host_port);

        socket_ = socket;

        timer_ = std::make_unique<asio::steady_timer>(ioc);
        schedule_timer();

        return true;
    }


    void stop(){
        enabled_ = false;
        if(timer_){
            timer_->cancel();
        }
    }


    [[nodiscard]] bool is_enabled() const{
        return enabled_;
    }


    void update_circuit(uint64_t cid,
                        const std::vector<std::string>& relay_eps,
                        const std::string& exit_ep,
                        const std::string& dest = ""){
        if(!enabled_)
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& c: circuits_){
            if(c.cid == cid){
                c.relays = relay_eps;
                c.exit = exit_ep;
                if(!dest.empty())
                    c.dest = dest;
                return;
            }
        }
        circuits_.push_back({cid, relay_eps, exit_ep, dest});\
    }


    void remove_circuit(uint64_t cid){
        if(!enabled_)
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase_if(circuits_, [cid](const CircuitRecord& c){
            return c.cid == cid;
        });
    }


    void send_telemetry(){
        if(!enabled_ || !socket_ || !socket_->is_open())
            return;

        auto buffer = std::make_shared<std::string>(build_telemetry_json());

        log_info("sending telemetry list to demo server...");

        socket_->async_send_to(
            asio::buffer(*buffer),
            target_endpoint_,
            [this, keep_alive = buffer](const boost::system::error_code& ec, std::size_t bytes_sent){
                if(ec){
                    log_error("failed to send telemetry to {}:{} ({}): {}",
                              target_endpoint_.address().to_string(),
                              target_endpoint_.port(),
                              ec.value(),
                              ec.message());
                }
                else{
                    log_debug("sent {} bytes to {}:{}",
                              bytes_sent,
                              target_endpoint_.address().to_string(),
                              target_endpoint_.port());
                }
            }
        );
    }


    [[nodiscard]] asio::ip::address get_demo_addr() const{
        return asio::ip::make_address(target_endpoint_.address().to_string());
    }

private:
    struct CircuitRecord{
        uint64_t cid;
        std::vector<std::string> relays;
        std::string exit;
        std::string dest;
    };


    DemoReporter() = default;


    quill::Logger* logger_{nullptr};


    void schedule_timer(){
        if(!enabled_ || !timer_)
            return;
        timer_->expires_after(std::chrono::seconds(2));
        timer_->async_wait([this](const boost::system::error_code& ec){
            if(!ec && enabled_){
                send_telemetry();
                schedule_timer();
            }
        });
    }


    static std::string extract_endpoint(const std::string& raw){
        const std::string key = "endpoint: ";
        auto pos = raw.find(key);
        if(pos == std::string::npos){
            return raw;
        }
        pos += key.size();
        auto end = raw.find_first_of(",}", pos);
        return raw.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    }


    std::string build_telemetry_json(){
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream ss;
        ss << "{\n"
            << R"(  "node_id": ")" << node_id_ << "\",\n"
            << R"(  "role": ")" << role_str_ << "\",\n"
            << "  \"port\": " << listen_port_ << ",\n"
            << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() << ",\n"
            << "  \"circuits\": [";

        for(size_t i = 0; i < circuits_.size(); ++i){
            const auto& c = circuits_[i];
            ss << "\n    {"
                << "\"cid\": " << c.cid << ", "
                << "\"relays\": [";

            for(size_t j = 0; j < c.relays.size(); ++j){
                ss << "\"" << extract_endpoint(c.relays[j]) << "\"";
                if(j + 1 < c.relays.size())
                    ss << ", ";
            }

            ss << "], "
                << R"("exit": ")" << extract_endpoint(c.exit) << "\"";
            if(!c.dest.empty()){
                ss << R"(, "dest": ")" << c.dest << "\"";
            }
            ss << "}";
            if(i + 1 < circuits_.size())
                ss << ",";
        }
        ss << "\n  ]\n}";
        return ss.str();
    }


    bool enabled_{false};
    std::string node_id_;
    std::string role_str_;
    uint16_t listen_port_{0};
    asio::ip::udp::endpoint target_endpoint_;
    std::shared_ptr<asio::ip::udp::socket> socket_;
    std::unique_ptr<asio::steady_timer> timer_;
    std::mutex mutex_;
    std::vector<CircuitRecord> circuits_;


    template<typename... Args>
    void log_warn(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_WARNING(logger_, "[DemoReporter] {}",
                        fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_error(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_ERROR(logger_, "[DemoReporter] {}",
                      fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_info(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_INFO(logger_, "[DemoReporter] {}",
                     fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_debug(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_DEBUG(logger_, "[DemoReporter] {}",
                      fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }
};
} // namespace telemetry
