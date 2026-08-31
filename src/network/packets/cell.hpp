#pragma once
#include <cstdint>
#include <vector>


/*
K_R: public key of relay
K_E: public key of exit

SH_CE: shared key between client and exit
SH_CR: shared key between client and relay

eK_C: Client's fresh ephemeral public key (generated once per session)
eK_E: Exit's fresh ephemeral public key (generated once per session)
Sign_X(): Signature created using X's long-term private key
shared keys can be computed using eK_R and eK_C. eK is generated using x * G, where x is a secret and G is something we don't care about.
shared keys become: x*y*G == y*x*G, where x and y are secret keys of client and exit

* Setup
CLIENT to RELAY -> eK_C1
RELAY to CLIENT -> eK_R, Sign_R(eK_R || eK_C1)

CLIENT to RELAY -> SH_CR(send to exit: eK_C2)
RELAY to EXIT   -> client says: eK_C2

EXIT to RELAY   -> send to client: eK_E, Sign_E(eK_E || eK_C2)
RELAY to CLIENT -> SH_CR(exit says: eK_E, Sign_E(eK_E || eK_C2))


* Talking
* clients and relays map session_id to SH_CR if the same client uses the same relay for different circuits
* exits can figure out SH_CE using circuit_id in the unencrypted TransitHeader

define APP_Internal = APP_InternetProtocol + APP_TransportProtocol + APP_Encrypt(APP_Payload)

CLIENT to RELAY -> session_id + SH_CR(TransitHeader + SH_CE(PayloadHeader + APP_Internal))
RELAY to EXIT -> TransitHeader + SH_CE(PayloadHeader + APP_Internal)
EXIT to DEST -> APP_Encrypt(APP_Payload)

DEST to EXIT -> APP_Encrypt(APP_Payload)
EXIT to RELAY -> TransitHeader + SH_CE(PayloadHeader + APP_Internal)
RELAY to CLIENT -> session_id + SH_CR(TransitHeader + SH_CE(PayloadHeader + APP_Internal))

actual EXIT to DEST (observed by snooper) -> NEW_APP_InternetProtocol + NEW_APP_TransportProtocol + APP_Encrypt(APP_Payload), NEW_APP -> managed by EXIT's OS.
actual DEST to EXIt (observed by snooper) -> NEW_APP_InternetProtocol + NEW_APP_TransportProtocol + APP_Encrypt(APP_Payload), NEW_APP -> managed by DEST's OS.
*/

#pragma pack(push, 1)       // ? START: Tell compiler not to optimize this to 2^n bytes using padding

struct TransitHeader{
    uint64_t circuit_id;    // 8 Bytes: Circuit ID, each (client app -> exit) connection has a circuit id
    uint16_t frame_len;     // 2 Bytes: The size of the PayloadHeader + payload
    uint8_t flags;          // 1 Byte: Define later on.
};

struct PayloadHeader{
    uint32_t ip_protocol;   // 4 Bytes: Identifies the protocol which the underlying client packet follows (like the 4 byte header mac prepends in utun)
    uint64_t sequence_id;   // 8 Bytes: Sequence ID, each Circuit ID uses a Sequence ID, for reordering at exit etc.
    uint16_t packet_id;     // 2 Bytes: If the packet which is being sent is too large, we split it into many different packets. To distinguish from differnt large packets, we have packet_id
    uint8_t frag_index;     // 1 Byte: Index of this fragment in the huge packet.
    uint8_t frag_total;     // 1 Byte: Total number of fragments made from the huge packet.
    uint16_t payload_len;   // 2 Bytes: Actual payload bytes in this cell.
};

#pragma pack(pop)           // ? END


struct ClientRelayCell{
    uint32_t session_id;    // 4 Bytes: for client and relays to figure out which shared key to use if they are connected in multiple circuits
    std::vector<uint8_t> payload;   // TransitHeader + PayloadHeader + app data
};

struct RelayExitCell{
    TransitHeader thdr;
    std::vector<uint8_t> payload;   // PayloadHeader + app data
};