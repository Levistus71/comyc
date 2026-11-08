#include <iostream>
#include "src/network/sockets/hole_puncher.hpp"

using namespace comyc::network::sockets;
using namespace comyc::ice_server;

int main() {
    HolePuncher puncher;
    if (!puncher.init(0)) {
        std::cerr << "Failed to open socket!" << std::endl;
        return 1;
    }

    IceCandidate local_cand{"127.0.0.1", 0, CandidateType::HOST, 1000};
    IceCandidate server_cand{"127.0.0.1", 3478, CandidateType::SERVER_REFLEXIVE, 500};

    puncher.add_candidate_pair(local_cand, server_cand);

    std::cout << "[Test] Attempting hole punch probe..." << std::endl;
    if (!puncher.punch_holes(10, 50)) {
        std::cout << "[Test] Hole punching failed." << std::endl;
    }

    return 0;
}