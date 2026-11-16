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

* we don't want to duplicate the compute_packet_info (nt) work.
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

* this wouldn't work in multithreaded applications though. pioneer packet could call this handler *AFTER* this pushes
  the handler onto the map, but *BEFORE* the co_routine frame is set up. so we use asio::experimental::channel to send
  the val computed by the pioneer packet to all other waiting packets.


## 2. So strange:

works on mac and linux:

```c++

{
    if(!packet){
        LOG_ERROR(logger_, "listenv6 was called with null packet.");
        return;
    }
    
    auto recv_buf = asio::buffer(packet->payload);
        
    udp_socketv6_->async_receive_from(
        recv_buf,
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
        pkt->bytes_received = bytes_received;
        me->loop_listen(std::move(pkt), ec, false);
        }
    );
}

```

works on mac, segfaults on linux:
``` c++

{
    if(!packet){
        LOG_ERROR(logger_, "listenv6 was called with null packet.");
        return;
    }
    
    udp_socketv6_->async_receive_from(
        packet->payload,
        (*sender_endpoint_),
        [me=shared_from_this(), pkt = std::move(packet)](const boost::system::error_code& ec, const size_t bytes_received) mutable{
        pkt->bytes_received = bytes_received;
        me->loop_listen(std::move(pkt), ec, false);
        }
    );
}
```


so strange. linux first moved the packet into the payload and wrote the argument, mac wrote the argument first and then moved it into the lambda. same compiler (gcc) for both, (homebrew on mac). explanation

```md 

In C++, function argument evaluation order is unspecified (even in C++17 and C++20, while subexpressions within a single argument are sequenced, different arguments to the same function call can be evaluated in any order—usually right-to-left on x86_64 SysV ABI and left-to-right on ARM64 AAPCS64).

Look at the two arguments passed to async_receive_from:

* Argument 1: packet->payload (which implicitly converts to asio::mutable_buffer, dereferencing packet)

* Argument 3: [me=shared_from_this(), pkt = std::move(packet)](...) (which moves packet, leaving packet == nullptr)

* On macOS (Apple Silicon / ARM64): GCC uses the ARM64 calling convention, which evaluates function arguments left-to-right. It evaluates packet->payload first (while packet is still valid), and then moves packet into the lambda.

* On Linux (x86_64): GCC uses the System V AMD64 ABI, which evaluates function arguments right-to-left. It constructs the lambda first—moving packet into pkt and nulling out packet—and then evaluates Argument 1 (packet->payload), dereferencing a moved-from nullptr and immediately segfaulting.

```