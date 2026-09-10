K_R: public key of relay \
K_E: public key of exit

SH_CE: shared key between client and exit \
SH_CR: shared key between client and relay

eK_C: Client's fresh ephemeral public key (generated once per session) \
eK_E: Exit's fresh ephemeral public key (generated once per session) \
Sign_X (): Signature created using X's long-term private key \
Shared keys can be computed using eK_R and eK_C. eK is generated using x * G, where x is a secret and G is something we
don't care about. \
Shared keys become: x *y*G == y *x*G, where x and y are secret keys of client and exit

## Setup

CLIENT to RELAY -> eK_C1 \
RELAY to CLIENT -> eK_R, Sign_R (eK_R || eK_C1)

CLIENT to RELAY -> SH_CR (send to exit: eK_C2) \
RELAY to EXIT -> client says: eK_C2

EXIT to RELAY -> send to client: eK_E, Sign_E (eK_E || eK_C2) \
RELAY to CLIENT -> SH_CR (exit says: eK_E, Sign_E (eK_E || eK_C2))

## Talking

* clients and relays map session_id to SH_CR if the same client uses the same relay for different circuits
* exits can figure out SH_CE using circuit_id in the unencrypted TransitHeader

define APP_Internal = APP_InternetProtocol + APP_TransportProtocol + APP_Encrypt (APP_Payload)

CLIENT to RELAY -> session_id + SH_CR (TransitHeader + SH_CE (PayloadHeader + APP_Internal)) \
RELAY to EXIT -> TransitHeader + SH_CE (PayloadHeader + APP_Internal) \
EXIT to DEST -> APP_Encrypt (APP_Payload)

DEST to EXIT -> APP_Encrypt (APP_Payload) \
EXIT to RELAY -> TransitHeader + SH_CE (PayloadHeader + APP_Internal) \
RELAY to CLIENT -> session_id + SH_CR (TransitHeader + SH_CE (PayloadHeader + APP_Internal))

actual EXIT to DEST (observed by snooper) -> NEW_APP_InternetProtocol + NEW_APP_TransportProtocol + APP_Encrypt
(APP_Payload), NEW_APP -> managed by EXIT's OS. \
actual DEST to EXIt (observed by snooper) -> NEW_APP_InternetProtocol + NEW_APP_TransportProtocol + APP_Encrypt
(APP_Payload), NEW_APP -> managed by DEST's OS.