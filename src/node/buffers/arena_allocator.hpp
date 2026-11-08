#pragma once

#include <queue>
#include <vector>

#include <boost/lockfree/queue.hpp>

#include <quill/Frontend.h>
#include <quill/LogMacros.h>


template<typename T>
class ArenaSlot;


template<typename T>
class ArenaAllocator{
public:
    explicit ArenaAllocator(const size_t capacity, const char* logger_name):
        capacity_(capacity),
        buffer_(capacity_),
        free_slots_que_(capacity_){
        logger_ = quill::Frontend::get_logger(logger_name);
        if(capacity_ == 0){
            LOG_ERROR(logger_, "[ArenaAllocator] Capacity should be > 0, recieved : {}", capacity);
            throw std::invalid_argument("Capacity should be > 0.");
        }
        for(size_t i = 0; i < capacity_; i++){
            if(!free_slots_que_.push(i)){
                LOG_ERROR(logger_, "[ArenaAllocator] boost::lockfree::queue.push(i) failed to allocate elements.");
                throw std::runtime_error("boost::lockfree::queue.push(i) failed to allocate elements.");
            }
        }
    }


    ArenaSlot<T> alloc();


    size_t get_slot_idx(const ArenaSlot<T>& ptr) const;


    void dealloc(T* item_ptr) noexcept;

private:
    const size_t capacity_;
    std::vector<T> buffer_;
    boost::lockfree::queue<size_t, boost::lockfree::fixed_sized<true>> free_slots_que_; // optimize: boost
    quill::Logger* logger_{nullptr};
};


template<typename T>
class ArenaSlot{
public:
    ArenaSlot() = default;


    ArenaSlot(T* ptr, ArenaAllocator<T>* arena_allocator) noexcept:
        ptr_{ptr},
        arena_allocator_(arena_allocator){}


    ~ArenaSlot(){
        if(ptr_ && arena_allocator_){
            try{
                arena_allocator_->dealloc(ptr_);
            }
            catch(...){
                // hmm
            }
        }
    }


    ArenaSlot(const ArenaSlot&) = delete;


    ArenaSlot& operator=(const ArenaSlot&) = delete;


    ArenaSlot(ArenaSlot&& other) noexcept{
        ptr_ = other.ptr_;
        other.ptr_ = nullptr;

        arena_allocator_ = other.arena_allocator_;
        other.arena_allocator_ = nullptr;
    }


    ArenaSlot& operator=(ArenaSlot&& other) noexcept{
        if(this != &other){
            if(ptr_ != other.ptr_ && ptr_ && arena_allocator_){
                try{
                    arena_allocator_->dealloc(ptr_);
                }
                catch(...){
                    // do nothing
                }
            }

            ptr_ = other.ptr_;
            arena_allocator_ = other.arena_allocator_;

            other.ptr_ = nullptr;
            other.arena_allocator_ = nullptr;
        }

        return *this;
    }


    [[nodiscard]] T* operator->() const noexcept{
        return ptr_;
    }


    [[nodiscard]] T& operator*() const noexcept{
        return *ptr_;
    }


    [[nodiscard]] T* get() const noexcept{
        return ptr_;
    }


    [[nodiscard]] explicit operator bool() const noexcept{
        return ptr_ != nullptr;
    }


    [[nodiscard]] bool operator==(std::nullptr_t) noexcept{
        return ptr_ == nullptr;
    }


    [[nodiscard]] bool operator!=(std::nullptr_t) noexcept{
        return ptr_ != nullptr && arena_allocator_ != nullptr;
    }


    T* release() noexcept{
        T* temp = ptr_;
        ptr_ = nullptr;
        return temp;
    }


    [[nodiscard]] ArenaAllocator<T>* get_allocator() const noexcept{
        return arena_allocator_;
    }

private:
    T* ptr_{nullptr};
    ArenaAllocator<T>* arena_allocator_{nullptr};
};


template<typename T>
ArenaSlot<T> ArenaAllocator<T>::alloc(){
    size_t slot_idx;
    if(!free_slots_que_.pop(slot_idx)){
        return ArenaSlot<T>(nullptr, nullptr);
    }

    auto raw_ptr = &buffer_[slot_idx];
    return ArenaSlot<T>(raw_ptr, this);
}


template<typename T>
size_t ArenaAllocator<T>::get_slot_idx(const ArenaSlot<T>& ptr) const{
    if(!ptr){
        LOG_ERROR(logger_, "[ArenaAllocator] ArenaSlot is nullptr, get_slot_idx().");
        throw std::invalid_argument("ArenaSlot is nullptr");
    }

    const T* item_ptr = ptr.get();
    const T* start_ptr = buffer_.data();
    const T* end_ptr = start_ptr + capacity_;

    if(item_ptr < start_ptr || item_ptr >= end_ptr){
        LOG_ERROR(logger_, "[ArenaAllocator] ArenaSlot is out of bounds, get_slot_idx().");
        throw std::invalid_argument("Pointer out of bounds for this ArenaAllocator.");
    }

    return static_cast<size_t>(item_ptr - start_ptr);
}


template<typename T>
void ArenaAllocator<T>::dealloc(T* item_ptr) noexcept{
    if(item_ptr == nullptr){
        return;
    }

    const T* start_ptr = reinterpret_cast<const T*>(buffer_.data());
    const T* end_ptr = start_ptr + capacity_;

    if(item_ptr < start_ptr || item_ptr >= end_ptr){
        LOG_ERROR(logger_, "[ArenaAllocator] ArenaSlot is out of bounds, dealloc().");
        return;
    }

    if(const auto slot_idx = static_cast<size_t>(item_ptr - start_ptr); !free_slots_que_.push(slot_idx)){
        LOG_ERROR(logger_, "[ArenaAllocator] free_slots_que_.push() failed, dealloc().");
    }
}


template<typename T>
class ArenaSlotMPMCLockfreeQueue{
public:
    explicit ArenaSlotMPMCLockfreeQueue(size_t capacity):
        queue_(capacity){}


    bool try_push(ArenaSlot<T> slot){
        if(!slot)
            return false;

        QueueItem item{slot.get(), slot.get_allocator()};

        if(queue_.push(item)){
            slot.release();
            return true;
        }

        return false;
    }


    std::optional<ArenaSlot<T>> try_pop(){
        QueueItem item;
        if(queue_.pop(item)){
            return ArenaSlot<T>(item.ptr, item.allocator);
        }
        return std::nullopt;
    }

private:
    struct QueueItem{
        T* ptr{nullptr};
        ArenaAllocator<T>* allocator{nullptr};
    };


    boost::lockfree::queue<QueueItem, boost::lockfree::fixed_sized<true>> queue_;
};


template<typename T>
class ArenaSlotQueue{
public:
    explicit ArenaSlotQueue(size_t capacity):
        capacity_(capacity){}


    bool try_push(ArenaSlot<T> slot){
        if(!slot)
            return false;

        QueueItem item{slot.get(), slot.get_allocator()};

        if(queue_.size() >= capacity_){
            return false;
        }

        queue_.push(item);
        slot.release();
        return true;
    }


    std::optional<ArenaSlot<T>> try_pop(){
        if(queue_.empty()){
            return std::nullopt;
        }

        QueueItem item = queue_.front();
        queue_.pop();
        return ArenaSlot<T>(item.ptr, item.allocator);
    }


private:
    struct QueueItem{
        T* ptr{nullptr};
        ArenaAllocator<T>* allocator{nullptr};
    };


    size_t capacity_;
    std::queue<QueueItem> queue_;
};
