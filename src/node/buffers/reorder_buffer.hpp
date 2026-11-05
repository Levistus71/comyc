#pragma once

#include <optional>
#include <vector>


template<typename T, typename seq_t = uint64_t>
class ReorderBuffer{
public:
    explicit ReorderBuffer(size_t capacity, seq_t start_seq = 0):
        buffer_(capacity),
        capacity_(capacity),
        head_(start_seq){
        if(capacity == 0)
            throw std::invalid_argument("Capacity must be > 0.");
    }


    [[nodiscard]] bool insert(seq_t seq, T&& item){
        auto diff = static_cast<std::make_signed_t<seq_t>>(seq - head_);
        if(diff < 0 || static_cast<size_t>(diff) >= capacity_)
            return false;

        size_t index = seq % capacity_;
        if(buffer_[index].has_value())
            return false;

        buffer_[index] = std::forward<T>(item);
        return true;
    }


    template<typename Callback>
    [[nodiscard]] bool insert_try_drain(seq_t seq, T&& item, Callback&& handler){
        if(!insert(seq, std::forward<T>(item)))
            return false;
        try_drain(std::forward<Callback>(handler));
        return true;
    }


    template<typename Callback>
    void try_drain(Callback&& handler){
        // todo: actual drain logic (waiting)
        while(buffer_[head_ % capacity_].has_value()){
            size_t index = head_ % capacity_;
            auto item = std::move(*buffer_[index]);
            buffer_[index].reset();
            handler(head_++, std::move(item));
        }
    }

private:
    std::vector<std::optional<T>> buffer_;
    const size_t capacity_;
    seq_t head_;
};
