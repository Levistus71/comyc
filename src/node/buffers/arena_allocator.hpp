#pragma once

#include <vector>

#include <boost/lockfree/queue.hpp>


template<typename T>
class ArenaAllocator : public std::enable_shared_from_this<ArenaAllocator<T>>{
public:
    // prevents non-shared_ptred ArenaAllocator
    template<typename... Args>
    static std::shared_ptr<ArenaAllocator<T>> create(Args&&... args){
        return std::make_shared<ArenaAllocator<T>>(std::forward<Args>(args)...);
    }


    struct ArenaDeleter{
        std::shared_ptr<ArenaAllocator<T>> keep_alive_arena;


        void operator()(T* ptr) const{
            if(keep_alive_arena && ptr){
                keep_alive_arena->dealloc(ptr);
            }
            else{
                if(!keep_alive_arena)
                    throw std::runtime_error("ArenaAllocator not alive while dealloc-ing ptr from it");
            }
        }
    };


    using ArenaLease = std::unique_ptr<T, ArenaDeleter>;


    ArenaLease alloc(){
        size_t slot_idx;
        if(!free_slots_que_.pop(slot_idx)){
            return nullptr;
        }

        auto raw_ptr = &buffer_[slot_idx];
        return ArenaItem(raw_ptr, ArenaDeleter{this->shared_from_this()});
    }


    size_t get_slot_idx(const ArenaLease& ptr) const{
        if(!ptr){
            throw std::invalid_argument("ArenaLease nullptr");
        }

        const T* item_ptr = ptr.get();
        const T* start_ptr = reinterpret_cast<const T*>(buffer_.data());
        const T* end_ptr = start_ptr + capacity_;

        if(item_ptr < start_ptr || item_ptr >= end_ptr){
            throw std::invalid_argument("Pointer out of bounds for this ArenaAllocator.");
        }

        return static_cast<size_t>(item_ptr - start_ptr);
    }

private:
    const size_t capacity_;
    std::vector<std::optional<T>> buffer_;
    boost::lockfree::queue<size_t, boost::lockfree::fixed_sized<true>> free_slots_que_; // optimize: boost


    explicit ArenaAllocator(const size_t capacity):
        capacity_(capacity),
        buffer_(capacity_),
        free_slots_que_(capacity_){
        if(capacity_ == 0){
            throw std::invalid_argument("Capacity should be > 0.");
        }
        for(size_t i = 0; i < capacity_; i++){
            if(!free_slots_que_.push(i)){
                throw std::runtime_error("boost::lockfree::queue.push(i) failed to allocate elements.");
            }
        }
    }


    void dealloc(T* item_ptr){
        if(item_ptr == nullptr){
            return;
        }

        const T* start_ptr = reinterpret_cast<const T*>(buffer_.data());
        const T* end_ptr = start_ptr + capacity_;

        if(item_ptr < start_ptr || item_ptr >= end_ptr){
            throw std::invalid_argument("Pointer out of bounds for this ArenaAllocator.");
        }

        if(size_t slot_idx = static_cast<size_t>(item_ptr - start_ptr); !free_slots_que_.push(slot_idx)){
            throw std::runtime_error("Failed to push slot index to lockfree queue during deallocation.");
        }
    }
};
