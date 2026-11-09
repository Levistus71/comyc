
/*
you see this in node/

static Node::control_send_wait_udp(packet information){
    ... send part

    // wait part:
    using namespace boost::asio::experimental::awaitable_operators;
    auto result = co_await (
        NOTE: async_wait_for_response(txn_id, asio::use_awaitable, relays_info_glb)
        ||
        timer.async_wait(asio::use_awaitable)
    );

    ... retry part
}

when the control packet arrives:
client.cpp:
handle_control_from_relay(){
    calls Node::resume_control_operation();
}

static Node::resume_control_operation(){
    RelaysInfoGlb::ResponseHandler our_handler;
    {
        auto& mut = relays_info_glb->registry_mutex_;
        std::lock_guard<std::mutex> lock(mut);
        auto it = relays_info_glb->pending_requests_.find(txn_id);
        if(it != relays_info_glb->pending_requests_.end()){
            our_handler = std::move(it->second);
            relays_info_glb->pending_requests_.erase(it);
        }
    }

    if(our_handler){
        // executing this our_handler resumes the waiting coroutine (which was put there by
        // async_wait_for_response (node.hpp)
        our_handler(boost::system::error_code{}, std::move(payload));
    }
}

*/


/*

template<class CompletionToken>
static auto async_wait_for_response(txn_id_t txn_id, CompletionToken&& token, const std::shared_ptr<RelaysInfoGlb>& relays_info_glb){
    using Signature = void(boost::system::error_code, std::vector<uint8_t>);

    // async_initiate<initiation, token>: gets the raw handle from token, passes it on to the initiation lambda
    // we can do whatever we want with the raw handle (called our_handle in this code)
    // NOTE: we should also implement when our_handle is canceled
    // cancellation may happen on another thread (timer thread) exactly when the packet arrives and the handler is called
    // State {.std::atomic<bool> executed} takes care of that.
    return asio::async_initiate<CompletionToken, Signature>(
        [txn_id, relays_info_glb](auto handler){
            auto cancel_slot = handler.get_cancellation_slot();

            struct State{
                decltype(handler) h;
                std::atomic<bool> executed{false};


                State(decltype(handler)&& h):
                    h(std::move(h)){}
            };
            auto state = std::make_shared<State>(std::move(handler));

            auto our_handler = [state](boost::system::error_code ec, std::vector<uint8_t> data){
                if(!state->executed.exchange(true)){
                    state->h(ec, std::move(data));  // execute the state->h by moving the received packet data
                }
            };

            if(cancel_slot.is_connected()){
                // our custom cancellation routine: remove txn_id from pending_requests_
                cancel_slot.assign([state, txn_id, relays_info_glb](asio::cancellation_type_t type){
                    if(type != asio::cancellation_type::none){
                        // remove from pending_requests_
                        {
                            std::lock_guard<std::mutex> lock(relays_info_glb->registry_mutex_);
                            relays_info_glb->pending_requests_.erase(txn_id);
                        }
                        // update exchange to prevent packet_thread from executing this handle
                        // NOTE: keep_state_alive now lives on the "timer thread" stack.
                        // if we used state->h(cancel), cancellation_slot::clear() runs, it destroys this lambda
                        // because this lambda now holds the last "state" shared_ptr (we erased our_handler from the
                        // unordered_map just before this), "state" is now deleted.
                        /*
                        use after free in this case:
                        Caller (asio internals):
                            // ref_count = 1
                            state->h(cancel)
                            // ref_count now drops to 0
                            crashes because state was freed (when the caller stack unrolls)
                        coroutine:
                            state is stored in completion lambda
                            when state->h(cancel) is called, completion lambda is deleted, dropping state->ref_count
                            to 0, freeing state

                        safe in this case:
                        Caller (asio internals):
                            // ref_count = 1
                            keep_state_alive = state;
                            // ref_count = 2
                            keep_state_alive->h(cancel);
                            // state gets deleted, ref_count drops to 1
                            now when caller's stack gets unrolled, it safely deletes the pointer.

                        auto keep_state_alive = state;
                        if(!keep_state_alive->executed.exchange(true)){
                            keep_state_alive->h(
                                boost::system::error_code(asio::error::operation_aborted),
                                std::vector<uint8_t>{}
                            );
                        }
                    }
                });
            }

            {
                std::lock_guard<std::mutex> lock(relays_info_glb->registry_mutex_);
                relays_info_glb->pending_requests_[txn_id] = std::move(our_handler);
            }
        },
        token
    );
}
*/

