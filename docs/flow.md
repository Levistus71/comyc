[ OS Application ]
│ (Generates IP Traffic)
▼
[ utun Interface ] (MTU set to ~1350B to prevent custom fragmentation)
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. ASYNC READ │
│ boost::asio::posix::stream_descriptor reads raw IP frame into a pre- │
│ allocated memory slice (std::span<uint8_t>) from utun. │
│ │
│ 2. EXIT & CIRCUIT MAPPING │
│ Inspect Destination IP / App rule to match the flow to its designated │
│ Exit Node, retrieving circuit_id, sequence_id++, and Exit key (SH_CE). │
│ │
│ 3. INNER ENCRYPTION (Exit Layer)                                            │
│ Attach PayloadHeader (contains circuit_id, sequence_id, packet_id). │
│ Encrypt raw IP payload in-place using Exit Key (SH_CE). │
│ │
│ 4. DYNAMIC RELAY ROUTING │
│ Select the optimal Relay (Relay A, Relay B, etc.) for this packet via │
│ round-robin or latency metrics. Retrieve session_id and Relay Key (SH_CR) │
│ bound to that Relay. │
│ │
│ 5. OUTER ENCRYPTION (Relay Layer)                                           │
│ Prepend TransitHeader (contains session_id). │
│ Encrypt frame in-place using Relay Key (SH_CR) -> ClientRelayFrame. │
│ │
│ 6. LOCK-FREE QUEUING & DISPATCH │
│ Push fully formed ClientRelayFrame onto the designated Relay socket's │
│ lock-free ring buffer (spsc_queue). │
│ │
│ 7. BATCH TRANSMISSION │
│ Socket worker thread drains queue via sendmmsg () / io_uring, blasting │
│ batches of 32/64 UDP datagrams over the physical wire. │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
[ Relay Node ]
│ 1. Reads UDP packet, inspects unencrypted session_id in TransitHeader.
│ 2. Decrypts outer layer using Relay Key (SH_CR).
│ 3. Reads routing target, replaces TransitHeader, forwards to Exit.
▼
[ Exit Node ]
│ 1. Reads TransitHeader to locate circuit_id in O (1) hash table.
│ 2. Decrypts inner payload using Exit Key (SH_CE).
│ 3. Validates PayloadHeader, passes packet to reassembly jitter buffer.
│ 4. Writes raw IP packet directly to OS utun device for NAT routing.
▼
[ Destination Server ] (e.g., google.com)

[ Destination Server ]
│ (Replies with IP Packet)
▼
[ Exit Node utun ]
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. NAT & CIRCUIT LOOKUP │
│ OS Kernel passes packet to Exit utun. Exit maps (Virtual IP, Port) back │
│ to original circuit_id and corresponding Exit Key (SH_CE). │
│ │
│ 2. INNER ENCRYPTION │
│ Wrap raw return IP packet with PayloadHeader -> Encrypt using SH_CE. │
│ │
│ 3. RELAY DISPATCH │
│ Select target Relay path bound to this circuit. Prepend TransitHeader │
│ and transmit RelayExitFrame over UDP. │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
[ Relay Node ]
│ Passes frame back to Client over active session_id connection.
▼
[ Client Node ]
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. BATCH RECEIVE │
│ recvmmsg () / io_uring reads incoming UDP datagrams into ring buffers. │
│ │
│ 2. OUTER DECRYPTION (Relay Layer)                                           │
│ Read unencrypted session_id, strip TransitHeader, and decrypt outer │
│ layer using Relay Key (SH_CR). │
│ │
│ 3. INNER DECRYPTION (Exit Layer)                                            │
│ Read circuit_id from PayloadHeader, decrypt payload using Exit Key │
│ (SH_CE), and verify AEAD tag. │
│ │
│ 4. REORDERING & INJECTION │
│ Order frames by sequence_id inside jitter buffer, extract raw return IP │
│ packet, and write directly into local utun via async_write (). │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
[ OS Network Stack / Client Application ]