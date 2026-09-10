#pragma once
#include <functional>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <boost/smart_ptr/atomic_shared_ptr.hpp>
#include <boost/smart_ptr/make_shared.hpp>

template<
    class Key,
    class Val,
    class Hash = std::hash<Key>,
    class KeyEqual = std::equal_to<Key>,
    class Allocator = std::allocator<std::pair<const Key, Val>>
>
class RCU_UMap {
public:
    using MapType = std::unordered_map<Key, Val, Hash, KeyEqual, Allocator>;

    RCU_UMap();

    std::shared_ptr<Val> get(const Key& k);
    void put(const Key& k, const Val& v);
    void put(const Key& k, Val&& v);

private:
    boost::atomic_shared_ptr<MapType> umap_;
    std::mutex write_lock_;
};



template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::RCU_UMap(){
    auto initial_map = boost::make_shared<MapType>();
    umap_.store(initial_map);
}

template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
std::shared_ptr<Val> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::get(const Key& k){
    if(auto local_umap = umap_.load()){
        auto it = local_umap->find(k);
        if(it!=local_umap->end()){
            // return std::shared_ptr<Val>(local_umap, const_cast<Val*>(&it->second));
            return std::shared_ptr<Val>(
                const_cast<Val*>(&it->second),
                [local_umap](Val*) {}
            );
        }
    }
    return nullptr;
}

template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, const Val& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? boost::make_shared<MapType>(*current_umap) : boost::make_shared<MapType>();
    
    (*new_umap)[k] = v;

    umap_.store(new_umap);
}

template<class Key, class Val, class Hash, class KeyEqual, class Allocator>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, Val&& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto current_umap = umap_.load();
    auto new_umap = current_umap ? boost::make_shared<MapType>(*current_umap) : boost::make_shared<MapType>();
    
    (*new_umap)[k] = std::move(v);

    umap_.store(new_umap);
}