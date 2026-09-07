#include "src/node/node_utils.hpp"


template<
    class Key,
    class Val,
    class Hash,
    class KeyEqual,
    class Allocator
>
RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::RCU_UMap(){
    auto t = std::make_shared<const std::unordered_map<Key, Val, Hash, KeyEqual, Allocator>>();
    umap_.store(t);
}

template<class Key,
    class Val,
    class Hash,
    class KeyEqual,
    class Allocator
>
std::shared_ptr<Val> RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::get(const Key& k){
    auto local_umap = umap_.load();

    if(auto it=local_umap->find(k);it!=local_umap->end()){
        return std::shared_ptr<const Val>(local_umap, &it->second)
    }
    return nullptr;
}

template<class Key,
    class Val,
    class Hash,
    class KeyEqual,
    class Allocator
>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, const Val& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto new_umap = std::make_shared<std::unordered_map<Key,Val,Hash,KeyEqual,Allocator>>(*(umap_.load()));
    (*new_umap)[k] = v;

    umap_.store(new_umap);
}

template<class Key,
    class Val,
    class Hash,
    class KeyEqual,
    class Allocator
>
void RCU_UMap<Key, Val, Hash, KeyEqual, Allocator>::put(const Key& k, Val&& v){
    std::lock_guard<std::mutex> lock(write_lock_);

    auto new_umap = std::make_shared<std::unordered_map<Key,Val,Hash,KeyEqual,Allocator>>(*(umap_.load()));
    (*new_umap)[k] = std::move(v);

    umap_.store(new_umap);
}