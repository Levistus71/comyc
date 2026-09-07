#pragma once
#include <functional>
#include <unordered_map>
#include <memory>


template<
    class Key,
    class Val,
    class Hash = std::hash<Key>,
    class KeyEqual = std::equal_to<Key>,
    class Allocator = std::allocator<std::pair<const Key, Val>>
>
class RCU_UMap{
public:
    RCU_UMap();

    std::shared_ptr<Val> get(const Key& k);
    void put(const Key& k, const Val& v);
    void put(const Key& k, Val&& v);

private:
    std::atomic<std::shared_ptr<const std::unordered_map<Key, Val, Hash, KeyEqual, Allocator>>> umap_;
    std::mutex write_lock_;
};
