#pragma once
#include <functional>
#include <unordered_map>
#include <memory>
#include <mutex>

#if !defined(__cpp_lib_atomic_shared_ptr) || __cpp_lib_atomic_shared_ptr < 201711L
#error "C++ library toolchain doesn't support std::atomic<std::shared_ptr>"
#endif


template<
    class Key,
    class Val,
    class Hash = std::hash<Key>,
    class KeyEqual = std::equal_to<Key>,
    class Allocator = std::allocator<std::pair<const Key, Val>>>
class RCU_UMap{
public:
    using MapType = std::unordered_map<Key, Val, Hash, KeyEqual, Allocator>;


    RCU_UMap();


    std::shared_ptr<Val> get(const Key& k);


    void put(const Key& k, const Val& v);


    void put(const Key& k, Val&& v);


    std::pair<std::shared_ptr<Val>, bool> put_if_absent(const Key& k, const Val& v);


    std::pair<std::shared_ptr<Val>, bool> put_if_absent(const Key& k, Val&& v);


    void erase(const Key& key);

private:
    std::atomic<std::shared_ptr<MapType>> umap_;
    std::mutex write_lock_;
};


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::RCU_UMap(){
    auto initial_map = std::make_shared<MapType>();
    umap_.store(initial_map);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::shared_ptr<Val> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::get(const Key& k){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            // keeps local_umap alive (control block of shared_ptr is of local_umap's)
            // creates the potiner to it->second (the pointer points to it->second though)
            return std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second));
        }
    }
    return nullptr;
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, const Val& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? std::make_shared<MapType>(*current_umap) : std::make_shared<MapType>();

    (*new_umap)[k] = v;

    umap_.store(new_umap);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, Val&& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? std::make_shared<MapType>(*current_umap) : std::make_shared<MapType>();

    (*new_umap)[k] = std::move(v);

    umap_.store(new_umap);
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::pair<std::shared_ptr<Val>, bool> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put_if_absent(const Key& k, const Val& v){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            return {std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second)), false};
        }
    }

    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(current){
        auto it = current->find(k);
        if(it != current->end()){
            return {std::shared_ptr<Val>(current, const_cast<Val*>(&it->second)), false};
        }
    }

    auto new_map = current ? std::make_shared<MapType>(*current) : std::make_shared<MapType>();
    auto [it, inserted] = new_map->emplace(k, v);

    umap_.store(new_map, std::memory_order_release);

    return {std::shared_ptr<Val>(new_map, &it->second), true};
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::pair<std::shared_ptr<Val>, bool> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put_if_absent(const Key& k, Val&& v){
    if(auto local_umap = umap_.load(std::memory_order_consume)){
        auto it = local_umap->find(k);
        if(it != local_umap->end()){
            return {std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second)), false};
        }
    }

    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(current){
        auto it = current->find(k);
        if(it != current->end()){
            return {std::shared_ptr<Val>(current, const_cast<Val*>(&it->second)), false};
        }
    }

    auto new_map = current ? std::make_shared<MapType>(*current) : std::make_shared<MapType>();
    auto [it, inserted] = new_map->emplace(k, std::move(v));

    umap_.store(new_map, std::memory_order_release);

    return {std::shared_ptr<Val>(new_map, &it->second), true};
}


template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::erase(const Key& key){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current = umap_.load(std::memory_order_relaxed);
    if(!current || current->find(key) == current->end()){
        return;
    }

    auto new_map = std::make_shared<MapType>(*current);
    new_map->erase(key);
    umap_.store(new_map, std::memory_order_release);
}
