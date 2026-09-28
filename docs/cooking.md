## The problem:
The client reads packets from the utun. We (the client) then parses the raw packet from the utun, obtaining a tuple of
{src_addr, dest_addr, src_port, dest_port}. We have multiple circuits active at once. Sending the packet through the *correct*
circuit *fastly* is of the utmost importance. Call the tuple nt (short for network-tuple). We wish to find out the circuit
information of the network tuple as fast as possible. Assume the circuit information is in a struct called circuit_info.
We're using Asio and c++ 20 (quite extensively I might add).

### Naive solution
1. Create an unordered_map.
2. When accessing the unordered_map, use mutex.

### Slightly optimized solution
1. shared locks while reading from the unordered_map
2. write locks while updating the unordered_map, all readers should wait until write's done.

### Our current solution
1. Create a RCU unordered_map (read-copy-update)
2. So we store an atomic pointer (call it umap_) to the unordered_map.
3. All readers use that umap_->find() to get values.
4. When a writer wants to modify umap_, they create a local copy (local_umap_), update the local_umap_
5. The writer thread then atomically puts local_umap_ into umap_. All new threads access that new map.
6. We passed a shared_ptr to the called to keep the value/map alive (standard RCU). look at code (node_utils.hpp).

### Proposed solution
As you can see, we use shared_ptrs quite extensively. This introduces false sharing -> cache bouncing. Bad.
Here's the proposed version:

1. create 1 atomic circuit_info* per circuit (at time of circuit creation)
2. store that atomic circuit_info* in the rcu umap.
3. asio queues/posts should never access that circuit_info* again. (We should guarantee this)
4. whenever a circuit is torn down, the writer thread (one performing the teardown) atomically swaps the atomic circuit_info* to nullptr. writer thread then deletes it from the umap.

This is not completely safe yet:
1. all asio posted tasks don't use circuit_info later, they don't get affected by step 4. 
2. all threads after step 4 either see a nullptr, or they don't find it in the unordered_map. 
3. this leaves us with one problem: multiple thread accessing atomic circuit_info* when one of the thread (a writer thread) atomically swaps it with a nullptr.

To fix this issue (3.), we do this:
```c++
// completed_yields is of type std::atomic<int> (or similar)
// old_circuit is the pointer to circuit's circuit_info which is being torn down
for (size_t i=0;i<num_threads;i++){
    // post a handler to each thread
    make_every_thread_run_this_lambda_once([old_circuit, completed_yields, num_threads](){
        // when this light lambda executes on worker thread X, thread X HAS YIELDED 
        // from whatever packet handler it was running.
        if (completed_yields->fetch_add(1, std::memory_order_acq_rel) + 1 == num_threads){
            // the LAST worker thread to yield executes the actual deletion safely
            delete old_circuit;
        }
    });
}
```

Why this works: all threads which were using circuit_info* should have yieled (become free) if they ran that lambda.
So all threads which were using old circuit_info* should have also yielded. IDK a way to do the make_every_thread_run_this_lambda_once()
yet, we'll see.