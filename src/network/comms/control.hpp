#pragma once
#include "src/network/packets/cell.hpp"

#include <type_traits>


enum class ControlMsgType : uint8_t{
    // intial handshake (client | relay)
    RELAY_HANDSHAKE_REQ  = 1,
    RELAY_HANDSHAKE_RESP = 2,

    // initial handshake (client | exit)
    EXIT_HANDSHAKE_REQ  = 3,
    EXIT_HANDSHAKE_RESP = 4,

    // flow control | circuit teardown
    CIRCUIT_FLOW_CONTROL = 5,
    CIRCUIT_CLOSE_NOTIFY = 6,

    // relay dfs
    RELAY_DISCOVERY_REQ  = 7,
    RELAY_DISCOVERY_RESP = 8,

    // heartbeat
    HEARTBEAT_PING = 9,
    HEARTBEAT_PONG = 10,

    // client asking relay to store exit information (client | relay)
    RELAY_SETUP_EXIT_REQ = 11,
    RELAY_SETUP_EXIT_RES = 12,

    // error
    CONTROL_ERROR = 13
};


// client | relay messages:
/*
{
    RoutingFlag
    session_id
    encrypted client_relay{
        transit header{
            circuit_id = -1
            frame_len
            flag = control_message_to/from_relay_to/from_client
            payload_tier
            _reserved_[3]
        }
        control header{
            _reserved_
            msg_type
            flags
            payload_len
            sequence_id
        }
        message body {}
    }
}
*/

// client | exit messages:
/*
{
    at exit:
    RoutingFlag
    transit header{
        circuit_id = dedicated circuit for messages
        frame_len
        flag = control_message_to/from_exit_to/from_client
        payload_tier
        _reserved_[3]
    }
    encrypted client_exit{
        control header{
            _reserved_
            msg_type
            flags
            payload_len
            sequence_id
        }
        message body {}
    }


    at relay:
    RoutingFlag
    session_id
    encrypted client_relay{
        transit header{
            circuit_id = dedicated circuit for messages
            frame_len
            flag = control_message_to_exit
            payload_tier
            _reserved_[3]
        }
        encrypted client_exit{
            control header{
                _reserved_
                msg_type
                flags
                payload_len
                sequence_id
            }
            message body {}
        }
    }
}
*/

using txn_id_t = uint64_t;


struct ControlHeader{
    // total 16 bytes
    uint8_t _reserved_[4];   // 4 bytes: reserved
    ControlMsgType msg_type; // 1 byte:  ControlMsgType
    uint8_t flags;           // 1 byte:  flags, define later on
    uint16_t payload_len;    // 2 bytes: payload length after this header
    txn_id_t txn_id;         // 8 bytes: transaction id for the messages
};

static_assert(sizeof(ControlHeader) == 16, "ControlHeader layout broken");
static_assert(std::is_trivially_copyable_v<ControlHeader>, "ControlHeader is not memcpy safe");
constexpr size_t CONTROL_HDR_SZ = sizeof(ControlHeader);


struct RelayHandshakeReq{
    session_id_t session_id_req;
    // todo: encryption stuff
};

static_assert(sizeof(RelayHandshakeReq) == 4, "RelayHandshakeReq layout broken");
static_assert(std::is_trivially_copyable_v<RelayHandshakeReq>, "RelayHandshakeReq not memcpy safe");


struct RelayHandshakeRes{
    session_id_t session_id_res;
    // todo: encryption stuff
};

static_assert(sizeof(RelayHandshakeRes) == 4, "RelayHandshakeRes layout broken");
static_assert(std::is_trivially_copyable_v<RelayHandshakeRes>, "RelayHandshakeRes not memcpy safe");


constexpr size_t MAX_RELAY_LIST_SZ = 16;
constexpr size_t MAX_RELAYS_PER_CIRCUIT = 5;


struct RelayListReq{
    uint16_t relays_requested; // 2 bytes: number of relays the new machine wants
    uint8_t _reserved_[2];     // 2 bytes: padding
};

static_assert(sizeof(RelayListReq) == 4, "RelayListReq layout broken");
static_assert(std::is_trivially_copyable_v<RelayListReq>, "RelayListReq not memcpy safe");


struct RelayCandidateRecord{
    uint32_t ipv4;          // 4 bytes: Big-endian IPv4 address
    uint16_t port;          // 2 bytes: Big-endian UDP port
    uint8_t nat;            // 1 byte:  0 = Open, 1 = Full Cone, 2 = Restricted, 3 = Symmetric
    uint8_t bandwidth_tier; // 1 byte:  Relay capacity tier
};

static_assert(sizeof(RelayCandidateRecord) == 8, "RelayCandidateRecord layout broken");
static_assert(std::is_trivially_copyable_v<RelayCandidateRecord>, "RelayCandidateRecord not memcpy safe");


struct RelayListRes{
    uint16_t count;                                 // 2 bytes: number of records returned
    uint8_t _reserved_[6];                          // 6 bytes: padding
    RelayCandidateRecord relays[MAX_RELAY_LIST_SZ]; // 128 bytes: relay information
};

static_assert(sizeof(RelayListRes) == 136, "RelayListRes layout broken");
static_assert(std::is_trivially_copyable_v<RelayListRes>, "RelayListRes not memcpy safe");


struct RelaySetupExitReq{
    circuit_id_t circuit_id; // 8 bytes: circuit_id
    uint32_t exit_ipv4;      // 4 bytes: ipv4 of exit
    uint16_t exit_port;      // 2 bytes: port of exit
    uint8_t _reserved_[2];   // 2 bytes: reserved
};

static_assert(sizeof(RelaySetupExitReq) == 16, "RelaySetupExitReq layout broken");
static_assert(std::is_trivially_copyable_v<RelaySetupExitReq>, "RelaySetupExitReq not memcpy safe");


struct RelaySetupExitRes{
    uint8_t status;        // 1 byte:  0 = ok, 1 = error
};

static_assert(sizeof(RelaySetupExitRes) == 1, "RelaySetupExitRes layout broken");
static_assert(std::is_trivially_copyable_v<RelaySetupExitRes>, "RelaySetupExitRes not memcpy safe");


struct RelayList{
    uint16_t count;                                      // 2 bytes: number of records returned
    uint8_t _reserved_[6];                               // 6 bytes: padding
    RelayCandidateRecord relays[MAX_RELAYS_PER_CIRCUIT]; // 40 bytes: relay information
};

static_assert(sizeof(RelayList) == 48, "RelayList layout broken");
static_assert(std::is_trivially_copyable_v<RelayList>, "RelayList not memcpy safe");


struct ExitHandshakeReq{
    uint32_t ipv4;                  // 4 bytes: private ip requested by client
    uint8_t _reserved_[4];          // 4 bytes: padding
    circuit_id_t requested_cid;     // 8 bytes: circuit id requested by client
    sequence_id_t start_seq_client; // 8 bytes: start sequence id used by the client
    RelayList relay_list;           // 48 bytes: relay list
    // todo: encryption
};

static_assert(sizeof(ExitHandshakeReq) == 72, "ExitCircuitCreateReq layout broken");
static_assert(std::is_trivially_copyable_v<ExitHandshakeReq>, "ExitCircuitCreateReq not memcpy safe");


struct ExitHandshakeRes{
    circuit_id_t confirmed_cid;   // 8 bytes: confirmed circuit id
    sequence_id_t start_seq_exit; // 8 bytes: start sequence id used by the exit
    uint32_t rob_window_size;     // 4 bytes: window capacity
    uint8_t status_code;          // 1 byte:  0 = ok, 1 = error
    uint8_t _reserved_[3];        // 3 bytes: padding
    // todo: encryption
};

static_assert(sizeof(ExitHandshakeRes) == 24, "ExitCircuitCreateRes layout broken");
static_assert(std::is_trivially_copyable_v<ExitHandshakeRes>, "ExitCircuitCreateRes not memcpy safe");
