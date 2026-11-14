#pragma once

#include <optional>
#include <vector>
#include <chrono>
#include <memory>
#include <utility>
#include <algorithm>
#include <cmath>
#include <stdexcept>

#include <boost/asio.hpp>

#include <quill/Logger.h>
#include <fmt/core.h>


namespace asio = boost::asio;


template<typename T, typename seq_t = uint64_t>
class ReorderBuffer : public std::enable_shared_from_this<ReorderBuffer<T, seq_t>>{
public:
    struct Settings{
        static constexpr size_t DUPACK_THRESHOLD = 3; // standard threshold for TCP fast retransmit
        static constexpr double WAIT_LIMIT = 0.8;
        static constexpr size_t ESTIMATED_CIRCUIT_RTT_START = 40000;
        static constexpr double MIN_JITTER = 5000.0;
        static constexpr double MAX_DELAY = 40000.0;
    };


    using clock_t = std::chrono::steady_clock;
    using duration_t = std::chrono::microseconds;


    explicit ReorderBuffer(asio::io_context& ioc,
                           size_t capacity,
                           seq_t start_seq = 0,
                           quill::Logger* logger = nullptr,
                           duration_t estimated_circuit_rtt = duration_t(Settings::ESTIMATED_CIRCUIT_RTT_START)):
        logger_(logger),
        timer_(ioc),
        buffer_(capacity),
        capacity_(capacity),
        head_(start_seq),
        smoothed_rtt_us_(static_cast<double>(estimated_circuit_rtt.count())),
        rtt_var_us_(smoothed_rtt_us_ / 4.0),
        timer_active_(false){
        if(capacity == 0)
            throw std::invalid_argument("Capacity must be > 0.");

        recalculate_rto_bounds();
    }


    [[nodiscard]] bool insert(seq_t seq, T&& item){
        auto diff = static_cast<std::make_signed_t<seq_t>>(seq - head_);
        if(diff < 0 || static_cast<size_t>(diff) >= capacity_){
            log_error("Couldn't insert: diff: {}, capacity: {}", diff, capacity_);
            return false;
        }

        size_t index = seq % capacity_;
        if(buffer_[index].has_value()){
            log_error("Couldn't insert: buffer_[index].has_value(): {}",
                      buffer_[index].has_value() ? "true" : "false");
            return false;
        }

        update_rtt_estimator();

        buffer_[index] = std::move(item);

        log_debug("Inserted into buffer successfully.");
        return true;
    }


    template<typename Callback>
    [[nodiscard]] bool insert_try_drain(seq_t seq, T&& item, Callback&& handler){
        if(!insert(seq, std::move(item))){
            log_error("insert failed.");
            return false;
        }
        try_drain(std::forward<Callback>(handler));
        log_debug("try_drain called successfully.");
        return true;
    }


    template<typename Callback>
    void try_drain(Callback&& handler){
        // drain all "ready" packets
        while(buffer_[head_ % capacity_].has_value()){
            if(timer_active_){
                timer_.cancel();
                timer_active_ = false;
            }

            size_t index = head_ % capacity_;
            auto slot = std::move(*buffer_[index]);
            buffer_[index].reset();
            handler(head_++, std::move(slot));
        }

        // check for further packets
        size_t ahead_count = count_buffered_ahead();
        if(ahead_count == 0){
            return; // buffer is clean;
        }

        // fast-retransmit trigger:
        // if 3 or more packets are buffered ahead of head_, TCP will generate 3 DupACKs anyway
        // skip head_ to trigger fast retransmit without waiting
        if(ahead_count >= Settings::DUPACK_THRESHOLD){
            if(timer_active_){
                boost::system::error_code ec;
                timer_.cancel();
                timer_active_ = false;
            }
            skip_missing_head_and_drain(std::forward<Callback>(handler));
            return;
        }

        // start timer
        if(!timer_active_){
            start_rto_bounded_timer(std::forward<Callback>(handler));
        }
    }


    void update_circuit_rtt(duration_t rtt_sample){
        double sample = static_cast<double>(rtt_sample.count());
        rtt_var_us_ = (0.75 * rtt_var_us_) + (0.25 * std::abs(smoothed_rtt_us_ - sample));
        smoothed_rtt_us_ = (0.875 * smoothed_rtt_us_) + (0.125 * sample);
        recalculate_rto_bounds();
    }


    [[nodiscard]] duration_t current_wait_time() const noexcept{
        return current_wait_limit_;
    }

private:
    asio::steady_timer timer_;
    std::vector<std::optional<T>> buffer_;
    const size_t capacity_;
    seq_t head_;

    duration_t current_wait_limit_{20000};
    clock_t::time_point last_arrival_time_;
    double smoothed_rtt_us_;
    double rtt_var_us_;

    bool timer_active_;

    quill::Logger* logger_{nullptr};


    void recalculate_rto_bounds(){
        // TCP Estimated RTO = SRTT + 4 * RTTVAR
        double estimated_rto = smoothed_rtt_us_ + (4.0 * rtt_var_us_);

        // wait limit set to 80% of TCP RTO (less than TCP RTO to prevent stalls)
        // clamped between 5ms (min jitter) and 40ms (max overlay delay)
        double target_wait = std::clamp(estimated_rto * Settings::WAIT_LIMIT, Settings::MIN_JITTER, Settings::MAX_DELAY);
        current_wait_limit_ = duration_t(static_cast<int64_t>(target_wait));
    }


    void update_rtt_estimator(){
        auto now = clock_t::now();
        if(last_arrival_time_.time_since_epoch().count() != 0){
            /*
                This measures packet inter-arrival jitter, not actual round-trip latency (RTT).
                Feeding inter-arrival times directly into Jacobson's RTT formula creates an artificial RTO bound
                rather than a true network RTT bound.

                todo: while sending the packet, send the time of sending
            */
            auto delta_us = std::chrono::duration_cast<std::chrono::microseconds>(now - last_arrival_time_).count();
            update_circuit_rtt(duration_t(delta_us));
        }
        last_arrival_time_ = now;
    }


    [[nodiscard]] size_t count_buffered_ahead() const noexcept{
        size_t count = 0;
        for(size_t offset = 1; offset < capacity_; ++offset){
            if(buffer_[(head_ + offset) % capacity_].has_value()){
                count++;
            }
        }
        return count;
    }


    template<typename Callback>
    void skip_missing_head_and_drain(Callback&& handler){
        size_t skipped = 0;
        while(!buffer_[head_ % capacity_].has_value() && skipped < capacity_){
            ++head_;
            skipped++;
        }

        try_drain(std::forward<Callback>(handler));
    }


    template<typename Callback>
    void start_rto_bounded_timer(Callback handler){
        timer_active_ = true;
        timer_.expires_after(current_wait_limit_);

        timer_.async_wait([self = this->shared_from_this(), handler = std::move(handler)](const boost::system::error_code& ec) mutable{
            if(ec){
                // timer canceled mostly
                return;
            }

            self->timer_active_ = false;

            self->skip_missing_head_and_drain(std::move(handler));
        });
    }


    [[nodiscard]] size_t find_first_buffered_offset() const noexcept{
        for(size_t offset = 1; offset < capacity_; ++offset){
            if(buffer_[(head_ + offset) % capacity_].has_value()){
                return offset;
            }
        }
        return 0;
    }


    template<typename... Args>
    void log_error(fmt::format_string<Args...> fmt_str, Args&&... args){
        if(logger_){
            LOG_ERROR(logger_, "[ReorderBuffer] {}",
                      fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_info(fmt::format_string<Args...> fmt_str, Args&&... args){
        if(logger_){
            LOG_INFO(logger_, "[ReorderBuffer] {}",
                     fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_debug(fmt::format_string<Args...> fmt_str, Args&&... args){
        if(logger_){
            LOG_DEBUG(logger_, "[ReorderBuffer] {}",
                     fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }
};
