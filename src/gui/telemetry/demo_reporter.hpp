#pragma once

#include "src/node/cli.hpp"
#include <boost/asio.hpp>
#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <chrono>
#include <sstream>

namespace telemetry {

namespace asio = boost::asio;

class DemoReporter {
public:
    static DemoReporter& instance() {
        static DemoReporter s_instance;
        return s_instance;
    }

    void init(asio::io_context& ioc, const std::shared_ptr<cli::CliOptions>& options) {
        if (!options || !options->demo_mode) {
            enabled_ = false;
            return;
        }

        enabled_ = true;
        role_str_ = std::string(cli::CliParser::role_to_string(options->role));
        node_id_ = role_str_ + "-" + std::to_string(options->listen_port ? options->listen_port : (reinterpret_cast<uintptr_t>(this) % 10000));
        listen_port_ = options->listen_port;

        boost::system::error_code ec;
        auto addr = asio::ip::make_address(options->demo_host_ip, ec);
        if (ec) {
            addr = asio::ip::make_address("127.0.0.1");
        }
        target_endpoint_ = asio::ip::udp::endpoint(addr, options->demo_host_port);

        socket_ = std::make_shared<asio::ip::udp::socket>(ioc);
        socket_->open(target_endpoint_.protocol(), ec);

        timer_ = std::make_unique<asio::steady_timer>(ioc);
        schedule_timer();
    }

    void stop() {
        enabled_ = false;
        if (timer_) {
            boost::system::error_code ec;
            timer_->cancel();
        }
        if (socket_ && socket_->is_open()) {
            boost::system::error_code ec;
            socket_->close(ec);
        }
    }

    bool is_enabled() const { return enabled_; }

    void record_circuit(uint64_t cid,
                        const std::string& relay_ep,
                        const std::string& exit_ep,
                        const std::string& dest = "") {
        if (!enabled_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& c : circuits_) {
            if (c.cid == cid) {
                c.relay = relay_ep;
                c.exit = exit_ep;
                if (!dest.empty()) c.dest = dest;
                return;
            }
        }
        circuits_.push_back({cid, relay_ep, exit_ep, dest});
    }

    void remove_circuit(uint64_t cid) {
        if (!enabled_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase_if(circuits_, [cid](const CircuitRecord& c) { return c.cid == cid; });
    }

    void send_telemetry() {
        if (!enabled_ || !socket_ || !socket_->is_open()) return;

        std::string json = build_telemetry_json();
        auto buffer = std::make_shared<std::string>(std::move(json));

        socket_->async_send_to(
            asio::buffer(*buffer),
            target_endpoint_,
            [buffer](const boost::system::error_code&, std::size_t) {
                // fire-and-forget
            }
        );
    }

private:
    struct CircuitRecord {
        uint64_t cid;
        std::string relay;
        std::string exit;
        std::string dest;
    };

    DemoReporter() = default;

    void schedule_timer() {
        if (!enabled_ || !timer_) return;
        timer_->expires_after(std::chrono::seconds(2));
        timer_->async_wait([this](const boost::system::error_code& ec) {
            if (!ec && enabled_) {
                send_telemetry();
                schedule_timer();
            }
        });
    }

    std::string build_telemetry_json() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream ss;
        ss << "{\n"
           << "  \"node_id\": \"" << node_id_ << "\",\n"
           << "  \"role\": \"" << role_str_ << "\",\n"
           << "  \"port\": " << listen_port_ << ",\n"
           << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count() << ",\n"
           << "  \"circuits\": [";

        for (size_t i = 0; i < circuits_.size(); ++i) {
            const auto& c = circuits_[i];
            ss << "\n    {"
               << "\"cid\": " << c.cid << ", "
               << "\"relay\": \"" << c.relay << "\", "
               << "\"exit\": \"" << c.exit << "\"";
            if (!c.dest.empty()) {
                ss << ", \"dest\": \"" << c.dest << "\"";
            }
            ss << "}";
            if (i + 1 < circuits_.size()) ss << ",";
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
};

} // namespace telemetry
