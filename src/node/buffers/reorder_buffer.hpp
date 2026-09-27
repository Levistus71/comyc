#pragma once

#include <src/network/packets/cell.hpp>
#include <src/node/node_utils.hpp>
#include <src/node/buffers/ring_buffer.hpp>
#include <src/node/buffers/arena_allocator.hpp>

#include <concepts>
#include <memory>

#include <quill/Frontend.h>
#include <quill/LogMacros.h>

#include <boost/lockfree/queue.hpp>
#include <boost/asio.hpp>


namespace asio = boost::asio;


template<typename Packet>
concept GoodPacket = requires(const Packet& p) {
    { p.get_seq_id() } noexcept -> std::same_as<sequence_id_t>;
    { p.get_circuit_id() } noexcept -> std::same_as<circuit_id_t>;
};


template<class Packet>
    requires GoodPacket<Packet>
class ReorderBuffer : public std::enable_shared_from_this<ReorderBuffer<Packet>>{
public:
    ReorderBuffer(const size_t buffer_pool_sz, const size_t per_circuit_pool_sz, const std::string& logger_name, asio::io_context& ioc):
        packet_pool_sz_(buffer_pool_sz),
        per_circuit_pool_sz_(per_circuit_pool_sz),
        ioc_(ioc){
        packet_pool_ = ArenaAllocator<Packet>::create(packet_pool_sz_);
        logger_ = quill::Frontend::get_logger(logger_name);
    }


    using ArenaPacketPtr = typename ArenaAllocator<Packet>::ArenaLease;


    ArenaPacketPtr alloc(){
        auto ret = packet_pool_->alloc();
        if(!ret){
            LOG_ERROR(logger_, "[ReorderBuffer] ArenaAllocator failed to alloc().");
        }
        return ret;
    }


    struct RingBufferSlot{
        ArenaPacketPtr packet_ptr;
        sequence_id_t seq_id;
        size_t arena_idx;
    };


    using InternalRB = RingBuffer<RingBufferSlot, sequence_id_t>;


    void reorder_and_deliver(ArenaPacketPtr packet_ptr){
        if(!packet_ptr){
            LOG_ERROR(logger_, "[ReorderBuffer] recieved nullptr packet_ptr in handle_packet().");
            return;
        }

        circuit_id_t circuit_id = packet_ptr->get_circuit_id();

        auto ring_buffer = cid_rb_umap_.get(circuit_id);
        if(!ring_buffer){
            // should already be created when circuit is created. call ReorderBuffer::make_new_circuit();
            LOG_ERROR(logger_, "[ReorderBuffer] unknown circuit_id : {}", circuit_id);
            return;
        }

        reorder(ring_buffer, std::move(packet_ptr));
    }


    void make_new_circuit(circuit_id_t circuit_id, sequence_id_t start_seq){
        if(cid_rb_umap_.get(circuit_id)){
            LOG_ERROR(logger_, "[ReorderBuffer] Tried making new circuit with same id.");
            return;
        }

        std::shared_ptr<InternalRB> rb = std::make_shared<InternalRB>(per_circuit_pool_sz_, start_seq);
        auto [_, flag] = cid_rb_umap_.put_if_absent(circuit_id, rb);
        if(!flag){
            LOG_ERROR(logger_, "[ReorderBuffer] Tried making new circuit with same id.");
        }
    }

private:
    size_t packet_pool_sz_;
    std::shared_ptr<ArenaAllocator<Packet>> packet_pool_;

    size_t per_circuit_pool_sz_;
    RCU_UMap<circuit_id_t, std::shared_ptr<InternalRB>> cid_rb_umap_;

    quill::Logger* logger_{nullptr};
    asio::io_context& ioc_;

    /*

    struct PendingCircuitState{
        std::atomic<bool> is_building{true};
        boost::lockfree::queue<ArenaPacketPtr, boost::lockfree::fixed_sized<true>> pending_packets;


        explicit PendingCircuitState(size_t queue_size):
            pending_packets(queue_size){}
    };


    RCU_UMap<circuit_id_t, PendingCircuitState> pending_circuit_umap_;

    void make_new_ring_buffer(ArenaPacketPtr packet_ptr){
        circuit_id_t cid = packet_ptr->get_circuit_id();

        // check if necessary
        {
            std::shared_ptr<std::shared_ptr<InternalRB>> check = cid_rb_umap_.get(cid);
            if(check){
                reorder(check, std::move(packet_ptr));
                return;
            }
        }

        std::shared_ptr<PendingCircuitState> state = pending_circuit_umap_.get(packet_ptr->get_circuit_id());

        if(state){
            state->pending_packets.push(std::move(packet_ptr));

            // edge-case: if pioneer finished right as we pushed
            if(!state->is_building.load(std::memory_order_acquire)){
                std::shared_ptr<std::shared_ptr<InternalRB>> rb = cid_rb_umap_.get(cid);
                if(rb){
                    ArenaPacketPtr buffered_pkt = nullptr;
                    while(state->pending_packets.pop(buffered_pkt)){
                        asio::post(
                            ioc_,
                            [me=this->shared_from_this(), temp_rb = rb, temp_pkt = std::move(buffered_pkt)]() mutable{
                                me->reorder(temp_rb, std::move(temp_pkt));
                            }
                        );
                    }
                }
                else{
                    LOG_ERROR(logger_, "[ReorderBuffer] logic error in making new buffer.");
                }
            }
            return;
        }

        auto new_state = PendingCircuitState(per_circuit_pool_sz_);
        auto [state_check, pioneer] = pending_circuit_umap_.put_if_absent(cid, new_state);

        if(!pioneer){
            if(state_check){
                state_check->pending_packets.push(std::move(packet_ptr));

                // same edge case: if pioneer finishes just after we pushed
                if(!state_check->is_building.load(std::memory_order_acquire)){
                    std::shared_ptr<std::shared_ptr<InternalRB>> rb = cid_rb_umap_.get(cid);
                    if(rb){
                        ArenaPacketPtr buffered_pkt = nullptr;
                        while(state_check->pending_packets.pop(buffered_pkt)){
                            asio::post(
                                ioc_,
                                [me=this->shared_from_this(), temp_rb = rb, temp_pkt = std::move(buffered_pkt)]() mutable{
                                    me->reorder(temp_rb, std::move(temp_pkt));
                                }
                            );
                        }
                    }
                    else{
                        LOG_ERROR(logger_, "[ReorderBuffer] logic error in making new buffer.");
                    }
                }
            }
            return;
        }


        auto new_rb = std::make_shared<InternalRB>(per_circuit_pool_sz_, ); //todo: start_seq_id
        cid_rb_umap_.put(cid, new_rb);
        std::shared_ptr<std::shared_ptr<InternalRB>> final_rb = cid_rb_umap_.get(cid, final_rb);


        ArenaPacketPtr buffered_packet;
        while(state_check.pending_packets.pop(buffered_packet)){
            asio::post(
                ioc_,
                [me=this->shared_from_this(), temp_rb = final_rb, temp_pkt = std::move(buffered_packet)]() mutable{
                    me->reorder(temp_rb, std::move(temp_pkt));
                }
            );
        }

        state_check->is_building.store(false, std::memory_order_release);
        pending_circuit_umap_.erase(cid);
        reorder(final_rb, packet_ptr);
    }

    */

    void reorder(std::shared_ptr<std::shared_ptr<InternalRB>> ring_buffer_wrapper,
                 ArenaPacketPtr packet_ptr){
        std::shared_ptr<InternalRB> ring_buffer = ring_buffer_wrapper->get();

        size_t arena_idx;
        try{
            arena_idx = packet_pool_->get_slot_idx(packet_ptr);
        }
        catch(const std::runtime_error& e){
            LOG_ERROR(logger_, "[ReorderBuffer] packet_pool_.get_slot_idx() failed: {}", e.what());
            return;
        }

        RingBufferSlot rbs{
            .packet_ptr = packet_ptr,
            .seq_id     = packet_ptr->get_seq_id(),
            .arena_idx  = arena_idx
        };

        ring_buffer->insert_try_drain(rbs.seq_id, rbs, /*todo: handler*/);
    }
};
