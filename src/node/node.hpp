#pragma once
#include "node/roles/client.hpp"
#include "node/roles/exit.hpp"
#include "node/roles/relay.hpp"
#include <memory>

class Node{
public:


private:
    std::unique_ptr<Client> client_;
    std::unique_ptr<Relay> relay_;
    std::unique_ptr<Exit> exit_;
};