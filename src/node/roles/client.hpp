#pragma once

/*
* Client proc:

connect to control_server
setup tun
analyze how many exits we need:
    1. for browser traffic, we can set up different exits based on the websites they're visiting
    2. for other apps, query for best exit and use that
query for relays for each exit node from control_server
if nat prohibits: connect to turn 
connect to those relays using stun/turn
set up 1 hop connection to exit
send traffic
send analytics to control_server periodically


what should we communicate with the control_server:
1. upload/download speeds
2. for demo purposes: what exits are we using, data being sent to each exit, circuit information for
    each client_ -> exit_ (like what relays we're using, data being sent to those relays etc)


*/



class Client{
public:
    Client();
    ~Client();

    void start();
    auto stop();

private:
    auto setup_tun();
    void start_();

    std::thread tun_worker_;
    std::atomic<bool> running_ = false;
    std::atomic<int> utun_sockfd_ = -1;
};