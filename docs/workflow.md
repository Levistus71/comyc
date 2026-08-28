### Phase 1: Infrastructure & Discovery Setup

* **Step 1: Node Registration & Network Diagnostics (STUN / Central Server)**
* Upon startup, Client $U$ and candidate Entry Relays connect to a central signaling server.
* Nodes execute an automated STUN test to determine their public IP/port and NAT type (Full-Cone, Restricted Cone, or Symmetric).
* Entry Relays run periodic upstream/downstream bandwidth tests and report their availability and network metrics to the central directory.


* **Step 2: Relay-to-Relay Connectivity & Hole Punching**
* When $U$ pairs with Entry Relays ($A$ and $B$), they perform UDP hole punching using STUN metadata.
* **Fallback Routing:** If an Entry Relay or Client sits behind a Symmetric NAT, the connection falls back to a TURN relay to ensure cell delivery.


* **Step 3: Exit Node Selection & Destination Telemetry**
* $U$ requests latency and throughput metrics for candidate Exit Nodes ($C$) relative to its target region/destination.
* To avoid exposing its target destination to the central server, $U$ fetches performance metrics via 1-hop anonymized probes routed through an intermediate relay node.


* **Step 4: Path Optimization (Top $N$ Entry Node Assignment)**
* $U$ queries the central directory for the **Top $N$ Entry Relays** (typically $N=2$) matching its latency and bandwidth requirements.
* The central server returns relay metadata (public IP/port, supported encryption parameters, NAT state) without knowing the final destination $U$ will ultimately select.

---

### Phase 2: Runtime Multipath Pipeline

* **Step 5: Multipath Dispatching ($U \to \text{Relays} \to C$)**
* Client $U$ alternates cell streams across Entry Relays $A$ and $B$ over independent UDP sockets.
* Entry Relays $A$ and $B$ receive cells, decrypt the outer layer using $K_A$/$K_B$, update the circuit identifier, and forward the payload to Exit Node $C$.


* **Step 6: Reassembly & Delivery at Exit Node ($C$)**
* Exit Node $C$ receives out-of-order UDP streams from Relays $A$ and $B$.
* $C$ decrypts the inner onion layer using key $K_C$ and inserts cells into a **sliding-window Jitter Buffer** sorted by sequence ID.
* Once reassembled, $C$ flushes contiguous IP packets out to the target destination server via raw sockets.
* **Symmetric Return Stream:** Download traffic from the target server follows the reverse pipeline ($C \to A/B \to U$), where $U$ reassembles packets before writing them back to the local `utun` interface.


* **Step 7: Packet Segmentation, Framing & Encryption**
* Raw IP packets captured from the `utun` interface are chunked into fixed-size COMYC binary payload cells and assigned a 64-bit sequence ID.
* **Layered Onion Encryption:**
1. **Inner Layer:** Payload encrypted using $K_C$ (shared key between $U$ and Exit Node $C$).
2. **Outer Layer:** Cell headers and inner payload encrypted using $K_A$ or $K_B$ (shared keys between $U$ and Relays $A$/$B$ respectively).


---


### Phase 3: Client OS Integration & Protocol Engine

* **Step 8: System Traffic Interception (`utun` / `TUN`)**
* Client $U$ instantiates a virtual TUN network interface (`utun` on macOS, `tun` on Linux) and updates local routing tables to capture outbound IP traffic.
* **DNS Leak Protection:** All OS DNS requests on port 53 are intercepted, encapsulated into COMYC cells, and routed through the onion pipeline to be resolved remotely by Exit Node $C$ (or an encrypted DNS-over-HTTPS resolver at $C$).


---

### Phase 4: Staging & Deployment Roadmap

* **Step 9: Real-World Beta Deployment & Testing**
* **Local Emulation:** Test $U \to A/B \to C$ on a single machine using `tc netem` (Linux) or `dnctl` (macOS) to inject artificial packet loss (1–3%) and latency jitter (20–50ms) to validate the Exit Jitter Buffer.
* **Containerized Field Test:** Deploy nodes across distinct cloud instances (e.g., AWS/DigitalOcean) or residential devices across different home networks to measure real-world multi-path throughput against standard 1-hop VPN and Tor baselines.