the main issue (for now) is U finding a fast, suitable Exit C for a particular destination without expressing it's
desire to talk to said destination. the main premise of this is "C not colluding". we first need to decide what this
service is going to be. this is actually a course project lol. keep that in mind.

1. if we frame this as a "reliable, trustable VPN company", then the company can host high performance C (exit relay)
   servers themselves. so the clients can perform standard 1 hop (using a client as a hop) to query information related
   to connection speeds from exit relays to the destination. we could do this using one central server, or individually
   query all C servers (connect to a average speed server, keep scanning for better alternatives). so this is easy. even
   if the VPN company wants to collude with their own exit relay servers acting as clients, we show that the probability
   of you being compromised is low (better than standard 1 hop VPNs). we can host stun servers. we can also provide the
   clients with suitable entry nodes given a target exit relay.

2. if we frame this as a "completely decentralized" project, then the client needs to find a suitable exit relay. we
   could use the same idea from p2p networks for file finding. instead of file_names, we could use IP addresses of
   destinations. we run into a few problems here.

- what if no other client talked to that destination before? the guid (destination_ip) would be empty.
- it's not possible asking every client "what's your connection speed / RTT to this destination". we could keep track of
  a few fast clients (clients are required to send network speed information to select (many) guid's).
- we query those fast clients, select the fastest among those, and help populate the guid (destination_ip) and mark it
  as ("not conclusive") or something. when some other client wants to talk to destination, it checks the guid
  (destination_ip). it immediately connects to that server. if it's marked "not conclusive", it looks for better
  alternatives in the background (by querying (using a one hop) to its routing table nodes). if it finds that one of the
  client is faster than the exit node it's using, it sends info to guid (destination_ip) with a flag ("somewhat
  conclusive") and connects using the faster node. as more and more people talk to the destination and more and more
  work is put, the better the connection to the destination would be.
- choosing entry clients wisely (fast, reliable, non-colluding with exit) is a challenge.