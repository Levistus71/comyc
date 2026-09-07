## 1. Async Thundering Herd problem

sample code:
```
void User::process_raw_packet(std::shared_ptr<RawPacket> raw_packet){
    PacketInfo& nt = raw_packet->nt;        // assume packet info only has destination_address
    if(!already_computed_info(nt)){
        compute_info(nt);                   // builds a new circuit using nt
    }

    // process packet
}

compute_info(PacketInfo& nt){
    if(already_computing_packet_info(nt)){
        idk what to do here. come back after some other thread finishes processing
        return
    }
    mark_computing_packet_info(nt);
    async_compute_packet_info(nt);
    // wake up other packet processing pipelines.
    return;
}
```

* we don't want to duplicate the compute_packet_info(nt) work.
* this is called the "thundering herd problem" it seems.

solution:
```
asio::awaitable<void> User::process_raw_packet(std::shared_ptr<RawPacket> raw_packet){
    PacketInfo& nt = raw_packet->nt;
    if(!already_computed_info(nt)){
        co_await compute_info(nt);
    }

    // further process packet
}

std::unordered_map<PacketInfo, std::vector<std::function<void()>>> pending_computations_;

asio::awaitable<void> compute_info(PacketInfo& nt){
    if(auto it = pending_computations_.find(nt); it!=pending_computations_.end()){
        // suspend current packet processing
        co_await asio::async_initiate<const asio::use_awaitable_t<>, void()>(
            [me=shared_from_this(), nt](auto handler){
                pending_computations_[nt].push_back(std::move(handler));
            },
            asio::use_awaitable
        );
        co_return;
    }

    pending_computations_[nt] = {};
    co_await async_compute_packet_info(nt);
    mark_info_computed(nt);
    auto waiting_handlers = std::move(pending_computations_[nt]);
    pending_computations_.erase(nt);

    for(auto& continuation : waiting_handlers){
        continuation(); // resumes co_await in suspended packets
    }
}
```

* this wouldn't work in multithreaded applications though. pioneer packet could call this handler *AFTER* this pushes the handler onto the map, but *BEFORE* the co_routine frame is set up. so we use asio::experimental::channel to send the val computed by the pioneer packet to all other waiting packets.