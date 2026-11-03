#pragma once

#include <cstdint>
#include <type_traits>


enum class ControlMsgType : uint8_t{
    // intial handshake (client | relay)
    RELAY_HANDSHAKE_REQ  = 1,
    RELAY_HANDSHAKE_RESP = 2,

    // initial handshake (client | exit)
    EXIT_CIRCUIT_CREATE_REQ  = 3,
    EXIT_CIRCUIT_CREATE_RESP = 4,

    // flow control | circuit teardown
    CIRCUIT_FLOW_CONTROL = 5,
    CIRCUIT_CLOSE_NOTIFY = 6,

    // relay dfs
    RELAY_DISCOVERY_REQ  = 7,
    RELAY_DISCOVERY_RESP = 8,

    // exit circuit
    EXIT_NEW_CIRCUIT_REQ  = 9,
    EXIT_NEW_CIRCUIT_RESP = 10,

    // heartbeat
    HEARTBEAT_PING = 11,
    HEARTBEAT_PONG = 12,

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


struct ControlHeader{
    // total 16 bytes
    uint32_t _reserved1_;    // 4 bytes: reserved
    ControlMsgType msg_type; // 1 byte:  ControlMsgType
    uint8_t flags;           // 1 byte:  flags, define later on
    uint16_t payload_len;    // 2 bytes: payload length after this header
    uint64_t sequence_id;    // 8 bytes: sequence_id for the messages
};


static_assert(sizeof(ControlHeader) == 16, "ControlHeader layout broken");
static_assert(std::is_trivially_copyable_v<ControlHeader>, "ControlHeader is not memcpy safe");
constexpr size_t CONTROL_HDR_SZ = sizeof(ControlHeader);


struct RelayHandshakeReq{
    session_id_t session_id_req;
    // encryption stuff
};


struct RelayHandshakeRes{
    // encryption stuff
};


constexpr size_t MAX_RELAY_LIST_SZ = 16;


struct RelayListReq{
    uint16_t relays_requested; // 2 bytes: number of relays the new machine wants
    uint8_t _reserved_[6];     // 6 bytes: padding
};


struct RelayCandidateRecord{
    uint32_t ipv4;          // 4 bytes: Big-endian IPv4 address
    uint16_t port;          // 2 bytes: Big-endian UDP port
    uint8_t nat;            // 1 byte:  0 = Open, 1 = Full Cone, 2 = Restricted, 3 = Symmetric
    uint8_t bandwidth_tier; // 1 byte:  Relay capacity tier
};


struct RelayListRes{
    uint16_t count;                                 // 2 bytes: number of records returned
    uint8_t _reserved_[6];                          // 6 bytes: padding
    RelayCandidateRecord relays[MAX_RELAY_LIST_SZ]; // 128 bytes: relay information
};
