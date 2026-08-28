### Executive Summary

**COMYC (Chopping Onions Makes You Cry)** is a multi-path UDP onion-routing network designed to aggregate bandwidth across parallel relay pipelines while preserving user privacy (kinda, better than VPNs, (significantly) worse than TOR).

Rather than routing traffic through a single sequential chain of relays (like traditional Tor), COMYC splits an application's raw IP packets across two (or more) independent entry paths ($A$ and $B$) before aggregating them at a high-performance Exit Node ($C$).

```
                      +---> [ Relay A ] ---+
                      |                    |
[ Client U ] (utun) --+                    +---> [ Exit Node C ] ---> [ Target Server ]
                      |                    |
                      +---> [ Relay B ] ---+

```

By decoupling identity from destination and using parallel transport pipelines, COMYC aims to overcome the single-path throughput bottlenecks of standard onion networks.

---

### Network Architecture & Node Roles

* **Client ($U$):**
Captures system-wide network traffic, serializes raw IP packets into COMYC data cells, applies layered onion encryption, and splits outgoing cells based on traffic data across Entry Relays. Reassembles incoming return streams.
* **Entry Relays:**
Stateless intermediate nodes. They receive encrypted cell streams from $U$, strip one layer of encryption, swap circuit identifiers, and forward the cells to Exit Node $C$. They can be clients too, using another batch of entry relays. So $U$ -> user, entry relays -> users, exit relays -> users/hosted by the vpn company.
* *Knowledge Scope:* The Entry Relays know $U$'s IP address and $C$'s IP address, but **do not know the final destination or packet contents**.


* **Exit Node ($C$):**
A dedicated high-performance server. $C$ receives out-of-order UDP cells from the entry relays, reorders them using a sliding-window Jitter Buffer, strips the final onion layer, and writes raw IP packets to the target server. For return downloads, $C$ chops incoming streams, encrypts them, and alternates chunks back across $C \to Entry Relays \to U$.
* *Knowledge Scope:* Exit Node $C$ knows the final destination and payload, but **does not know $U$'s real IP address** (only seeing the Entry Relays' IP).



---

### System Protocol & Packet Lifecycle (2 entry relays example)

```
[ Local App ]
     | (Raw IP Packet)
     v
[ Client U (utun) ]
     |
     +---> [Cell 1: Seq 1] ---> Encrypt(K_A, K_C) ---> Relay A --+
     |                                                          |
     +---> [Cell 2: Seq 2] ---> Encrypt(K_B, K_C) ---> Relay B --+
                                                                |
                                                                v
                                                       [ Exit Node C ]
                                                                | (Reorder via Jitter Buffer)
                                                                v
                                                       [ Target Server ]

```

1. **Capture:** $U$'s engine intercepts raw IPv4/IPv6 packets.
2. **Segmentation & Sequence:** Packets are assigned a monotonically increasing id and wrapped in fixed-size COMYC binary cells.
3. **Multi-Layer Onion Encryption:** Cells are encrypted ($K_C$ inner layer, $K_A$/$K_B$ outer layer).
4. **Parallel Transmission:**
* **Pipeline 1:** $U \to A \to C$
* **Pipeline 2:** $U \to B \to C$


5. **Reassembly at $C$:** Exit Node $C$ places incoming cells into a sliding-window Jitter Buffer, sorts them by the id, extracts the inner IP packets, and forwards them to the destination.
6. **Symmetric Downstream Path:** Incoming return bytes from the target server are processed by $C$'s downstream engine, split across $C \to A \to U$ and $C \to B \to U$, and reassembled by $U$'s local buffer.

---

### Refined Threat Model & Security Scope

Because COMYC shifts intermediate pathing complexity into a dedicated 3-node topology, the attack surface narrows to specific, well-defined boundaries:

#### 1. The Collusion Threat Boundary

Anonymity is preserved as long as Exit Node $C$ does not collude with an entry relay.

* **Safe State (Honest Node $C$):** If $C$ is honest, $U$'s identity is cryptographically separated from the destination. Even if $A$ and $B$ are adversarial, they only know $U$ is transmitting data to $C$.
* **Compromised State ($C$ + $A$ or $B$ Collude):** If $C$ is adversarial and colludes with Relay $A$ or $B$, matching shared Circuit IDs unmasks $U \longleftrightarrow \text{Target Destination}$.

#### 2. To Add.

---