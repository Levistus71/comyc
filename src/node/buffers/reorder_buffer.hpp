#pragma once

#include <optional>
#include <vector>
#include <chrono>
#include <memory>
#include <utility>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <mutex>

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
        timer_(ioc),
        buffer_(capacity),
        capacity_(capacity),
        head_(start_seq),
        smoothed_rtt_us_(static_cast<double>(estimated_circuit_rtt.count())),
        rtt_var_us_(smoothed_rtt_us_ / 4.0),
        timer_active_(false),
        timer_generation_(0),
        logger_(logger){
        if(capacity == 0){
            throw std::invalid_argument("Capacity must be > 0.");
        }

        recalculate_rto_bounds();
    }


    [[nodiscard]] bool insert(seq_t seq, T&& item){
        std::unique_lock<std::mutex> lock(mtx_);
        return insert_locked(seq, std::move(item));
    }


    template<typename Callback>
    [[nodiscard]] bool insert_try_drain(seq_t seq, T&& item, Callback&& handler){
        std::unique_lock<std::mutex> lock(mtx_);
        if(!insert_locked(seq, std::move(item))){
            return false;
        }
        try_drain_locked(std::forward<Callback>(handler));
        return true;
    }


    template<typename Callback>
    void try_drain(Callback&& handler){
        std::unique_lock<std::mutex> lock(mtx_);
        try_drain_locked(std::forward<Callback>(handler));
    }


    void update_circuit_rtt(duration_t rtt_sample){
        std::unique_lock<std::mutex> lock(mtx_);
        update_circuit_rtt_locked(rtt_sample);
    }


    [[nodiscard]] duration_t current_wait_time() const noexcept{
        std::unique_lock<std::mutex> lock(mtx_);
        return current_wait_limit_;
    }


    void change_head(sequence_id_t new_head){
        std::unique_lock<std::mutex> lock(mtx_);
        head_ = new_head;
    }

private:
    mutable std::mutex mtx_;
    asio::steady_timer timer_;
    std::vector<std::optional<T>> buffer_;
    const size_t capacity_;
    seq_t head_;

    duration_t current_wait_limit_{20000};
    clock_t::time_point last_arrival_time_;
    double smoothed_rtt_us_;
    double rtt_var_us_;

    bool timer_active_;
    uint64_t timer_generation_;

    quill::Logger* logger_{nullptr};


    [[nodiscard]] bool insert_locked(seq_t seq, T&& item){
        auto diff = static_cast<std::make_signed_t<seq_t>>(seq - head_);
        if(diff < 0 || static_cast<size_t>(diff) >= capacity_){
            log_debug("Couldn't insert: diff: {}, capacity: {}, head: {}, seq: {}", diff, capacity_, head_, seq);
            log_warn("Couldn't insert, (mostly) buffer full.");
            return false;
        }

        size_t index = seq % capacity_;
        if(buffer_[index].has_value()){
            log_error("Couldn't insert: buffer_[index].has_value(): true (seq: {})", seq);
            return false;
        }

        update_rtt_estimator_locked();
        buffer_[index] = std::move(item);

        return true;
    }


    template<typename Callback>
    void try_drain_locked(Callback&& handler){
        // drain all "ready" packets
        while(buffer_[head_ % capacity_].has_value()){
            cancel_timer_locked();

            size_t index = head_ % capacity_;
            auto slot = std::move(*buffer_[index]);
            buffer_[index].reset();
            handler(head_++, std::move(slot));
        }

        // check for further packets
        size_t ahead_count = count_buffered_ahead_locked();
        if(ahead_count == 0){
            cancel_timer_locked();
            return; // buffer is clean
        }

        // fast-retransmit trigger:
        // if 3 or more packets are buffered ahead of head_, TCP will generate 3 DupACKs anyway
        // skip head_ to trigger fast retransmit without waiting
        if(ahead_count >= Settings::DUPACK_THRESHOLD){
            cancel_timer_locked();
            skip_missing_head_and_drain_locked(std::forward<Callback>(handler));
            return;
        }

        // start timer
        if(!timer_active_){
            start_rto_bounded_timer_locked(std::forward<Callback>(handler));
        }
    }


    void cancel_timer_locked(){
        ++timer_generation_;
        if(timer_active_){
            timer_.cancel();
            timer_active_ = false;
        }
    }


    void update_circuit_rtt_locked(duration_t rtt_sample){
        double sample = static_cast<double>(rtt_sample.count());
        rtt_var_us_ = (0.75 * rtt_var_us_) + (0.25 * std::abs(smoothed_rtt_us_ - sample));
        smoothed_rtt_us_ = (0.875 * smoothed_rtt_us_) + (0.125 * sample);
        recalculate_rto_bounds();
    }


    void recalculate_rto_bounds(){
        // TCP Estimated RTO = SRTT + 4 * RTTVAR
        double estimated_rto = smoothed_rtt_us_ + (4.0 * rtt_var_us_);

        // wait limit set to 80% of TCP RTO (less than TCP RTO to prevent stalls)
        // clamped between 5ms (min jitter) and 40ms (max overlay delay)
        double target_wait = std::clamp(estimated_rto * Settings::WAIT_LIMIT,
                                        Settings::MIN_JITTER,
                                        Settings::MAX_DELAY);
        current_wait_limit_ = duration_t(static_cast<int64_t>(target_wait));
    }


    void update_rtt_estimator_locked(){
        auto now = clock_t::now();
        if(last_arrival_time_.time_since_epoch().count() != 0){
            auto delta_us = std::chrono::duration_cast<std::chrono::microseconds>(now - last_arrival_time_).count();
            update_circuit_rtt_locked(duration_t(delta_us));
        }
        last_arrival_time_ = now;
    }


    [[nodiscard]] size_t count_buffered_ahead_locked() const noexcept{
        size_t count = 0;
        for(size_t offset = 1; offset < capacity_; ++offset){
            if(buffer_[(head_ + offset) % capacity_].has_value()){
                count++;
            }
        }
        return count;
    }


    template<typename Callback>
    void skip_missing_head_and_drain_locked(Callback&& handler){
        if(count_buffered_ahead_locked() == 0){
            return;
        }

        size_t skipped = 0;
        while(!buffer_[head_ % capacity_].has_value() && skipped < capacity_){
            ++head_;
            skipped++;
        }

        try_drain_locked(std::forward<Callback>(handler));
    }


    template<typename Callback>
    void start_rto_bounded_timer_locked(Callback handler){
        timer_active_ = true;
        const uint64_t gen = ++timer_generation_;
        timer_.expires_after(current_wait_limit_);

        timer_.async_wait([self = this->shared_from_this(),
                gen,
                handler = std::move(handler)](const boost::system::error_code& ec) mutable{
                std::unique_lock<std::mutex> lock(self->mtx_);
                if(ec || !self->timer_active_ || self->timer_generation_ != gen){
                    return;
                }

                self->timer_active_ = false;
                self->skip_missing_head_and_drain_locked(std::move(handler));
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
    void log_warn(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_WARNING(logger_, "[ReorderBuffer] {}",
                        fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_error(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_ERROR(logger_, "[ReorderBuffer] {}",
                      fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_info(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_INFO(logger_, "[ReorderBuffer] {}",
                     fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }


    template<typename... Args>
    void log_debug(fmt::format_string<Args...> fmt_str, Args&&... args) const{
        if(logger_){
            LOG_DEBUG(logger_, "[ReorderBuffer] {}",
                      fmt::format(fmt_str, std::forward<Args>(args)...));
        }
    }
};
