#pragma once

#include "src/node/node_utils.hpp"

#include <algorithm>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>


namespace cli{
struct CliOptions{
    NodeRole role = NodeRole::CLIENT_RELAY;
    uint16_t listen_port = 0; // 0 = OS assigned / ephemeral

    bool specified_bootstrap = false;
    std::string bootstrap_ip = "127.0.0.1";
    uint16_t bootstrap_port = 6969;

    bool specified_exit = false;
    std::string exit_ip = "8.8.8.8";
    uint16_t exit_port = 6969;

    size_t thread_count = std::max(1u, std::thread::hardware_concurrency());
    std::string log_file = "logs.txt";
    bool console_log = false;
    bool show_help = false;
    bool show_version = false;
    bool hijack_utun = true;
    bool bootstrap_node = false;

    bool demo_mode = false;
    std::string demo_host_ip = "127.0.0.1";
    uint16_t demo_host_port = 6969;
};


class CliParser{
public:
    static std::string_view role_to_string(NodeRole role) noexcept{
        switch(role){
            case NodeRole::CLIENT:
                return "client";
            case NodeRole::RELAY:
                return "relay";
            case NodeRole::EXIT:
                return "exit";
            case NodeRole::CLIENT_RELAY:
                return "client-relay";
            default:
                return "unknown";
        }
    }


    static std::optional<NodeRole> parse_role(std::string_view val) noexcept{
        std::string lower(val);
        std::ranges::transform(lower, lower.begin(), [](unsigned char c){
            return static_cast<char>(std::tolower(c));
        });

        if(lower == "relay"){
            return NodeRole::RELAY;
        }
        if(lower == "exit"){
            return NodeRole::EXIT;
        }
        if(lower == "client-relay" || lower == "client_relay" ||
           lower == "client+relay" || lower == "both"){
            return NodeRole::CLIENT_RELAY;
        }
        return std::nullopt;
    }


    static void print_version(){
        std::cout << "Comyc v0.1.0 (P2P Anonymizing Network Node)\n";
    }


    static void print_help(std::string_view prog_name){
        std::cout << "Usage: " << prog_name << " [OPTIONS]\n\n"
            << "Options:\n"
            << "  -r, --role <ROLE>            Node operational role [default: client-relay]\n"
            << "                                 client       : Initiates circuits & proxies traffic via utun\n"
            << "                                 relay        : Transit node forwarding cells between peers\n"
            << "                                 exit         : Egress node routing traffic to public destinations\n"
            << "                                 client-relay : Combined client and relay functionality\n"
            << "  -j, --hijack-off             Don't hijack system traffic [default: hijacks]\n"
            << "  -B, --imbootstrapbill        Start as a bootstrap node\n"
            << "  -p, --port <PORT>            UDP port to bind for incoming traffic [default: 0 (ephemeral)]\n"
            << "  -b, --bootstrap-ip <IP>      Bootstrap relay IPv4 address [default: 127.0.0.1]\n"
            << "      --bootstrap-port <PORT>  Bootstrap relay port [default: 6969]\n"
            << "  -e, --exit-ip <IP>           Exit IPv4 address [default: 8.8.8.8]\n"
            << "      --exit-port <PORT>       Exit port [default: 6969]\n"
            << "  -t, --threads <NUM>          Worker thread pool size [default: hardware concurrency ("
            << std::max(1u, std::thread::hardware_concurrency()) << ")]\n"
            << "  -l, --log-file <PATH>        Path to output log file [default: logs.txt]\n"
            << "  -c, --console-log            Enable logging to console/stdout in addition to file [default: false]\n"
            << "  -h, --help                   Print help information and exit\n"
            << "  -v, --version                Print version information and exit\n\n"
            << "Examples:\n"
            << "  " << prog_name << " --role client\n"
            << "  " << prog_name << " --role relay --port 8080 --console-log\n"
            << "  " << prog_name << " --role exit --port 9000 --threads 4\n"
            << "  " << prog_name << " -r client-relay -p 7000 -b 10.0.0.1 --bootstrap-port 8080\n\n";
    }


    static std::optional<CliOptions> parse(int argc, char* argv[]){
        CliOptions opts;
        std::string_view prog_name = (argc > 0 && argv[0]) ? argv[0] : "node";

        for(int i = 1; i < argc; ++i){
            std::string_view arg = argv[i];

            if(arg == "-h" || arg == "--help"){
                opts.show_help = true;
                return opts;
            }
            if(arg == "-v" || arg == "--version"){
                opts.show_version = true;
                return opts;
            }
            if(arg == "-c" || arg == "--console-log"){
                opts.console_log = true;
                continue;
            }
            if(arg == "-B" || arg == "--imbootstrapbill"){
                opts.bootstrap_node = true;
                continue;
            }
            if(arg == "-j" || arg=="--hijack-off"){
                opts.hijack_utun = false;
                continue;
            }

            // Options taking a value
            std::string_view key;
            std::optional<std::string_view> inline_val;

            auto eq_pos = arg.find('=');
            if(eq_pos != std::string_view::npos){
                key = arg.substr(0, eq_pos);
                inline_val = arg.substr(eq_pos + 1);
            }
            else{
                key = arg;
            }

            auto get_value = [&](std::string_view opt_name) -> std::optional<std::string_view>{
                if(inline_val.has_value()){
                    return inline_val;
                }
                if(i + 1 < argc){
                    ++i;
                    return std::string_view(argv[i]);
                }
                std::cerr << "Error: Missing argument for option '" << opt_name << "'\n";
                return std::nullopt;
            };

            if(key == "-r" || key == "--role"){
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                auto parsed_role = parse_role(*val);
                if(!parsed_role){
                    std::cerr << "Error: Invalid role '" << *val << "'. Valid roles are: client-relay, relay, exit\n";
                    return std::nullopt;
                }
                opts.role = *parsed_role;
            }
            else if(key == "-p" || key == "--port"){
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                try{
                    int p = std::stoi(std::string(*val));
                    if(p < 0 || p > 65535){
                        std::cerr << "Error: Port must be in range 0 - 65535, got '" << *val << "'\n";
                        return std::nullopt;
                    }
                    opts.listen_port = static_cast<uint16_t>(p);
                }
                catch(...){
                    std::cerr << "Error: Invalid port number '" << *val << "'\n";
                    return std::nullopt;
                }
            }
            else if(key == "-b" || key == "--bootstrap-ip"){
                opts.specified_bootstrap = true;
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                opts.bootstrap_ip = std::string(*val);
            }
            else if(key == "--bootstrap-port"){
                opts.specified_bootstrap = true;
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                try{
                    int p = std::stoi(std::string(*val));
                    if(p <= 0 || p > 65535){
                        std::cerr << "Error: Bootstrap port must be in range 1 - 65535, got '" << *val << "'\n";
                        return std::nullopt;
                    }
                    opts.bootstrap_port = static_cast<uint16_t>(p);
                }
                catch(...){
                    std::cerr << "Error: Invalid bootstrap port '" << *val << "'\n";
                    return std::nullopt;
                }
            }
            else if(key=="-e" || key=="--exit-ip"){
                opts.specified_exit = true;
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                opts.exit_ip = std::string(*val);
            }
            else if(key=="--exit-port"){
                opts.specified_exit = true;
                auto val = get_value(key);
                try{
                    int p = std::stoi(std::string(*val));
                    if(p <= 0 || p > 65535){
                        std::cerr << "Error: Exit port must be in range 1 - 65535, got '" << *val << "'\n";
                        return std::nullopt;
                    }
                    opts.exit_port = static_cast<uint16_t>(p);
                }
                catch(...){
                    std::cerr << "Error: Invalid Exit port '" << *val << "'\n";
                    return std::nullopt;
                }
            }
            else if(key == "-t" || key == "--threads"){
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                try{
                    int t = std::stoi(std::string(*val));
                    if(t <= 0){
                        std::cerr << "Error: Threads must be greater than 0, got '" << *val << "'\n";
                        return std::nullopt;
                    }
                    opts.thread_count = static_cast<size_t>(t);
                }
                catch(...){
                    std::cerr << "Error: Invalid thread count '" << *val << "'\n";
                    return std::nullopt;
                }
            }
            else if(key == "-l" || key == "--log-file"){
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                opts.log_file = std::string(*val);
            }
            else if(key == "--demo"){
                opts.demo_mode = true;
            }
            else if(key == "--demo-host"){
                opts.demo_mode = true;
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                std::string s(*val);
                auto colon = s.find(':');
                if(colon != std::string::npos){
                    opts.demo_host_ip = s.substr(0, colon);
                    try{
                        opts.demo_host_port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
                    }
                    catch(...){
                        std::cerr << "Error: Invalid port in --demo-host '" << s << "'\n";
                        return std::nullopt;
                    }
                }
                else{
                    opts.demo_host_ip = s;
                }
            }
            else if(key == "--demo-port"){
                opts.demo_mode = true;
                auto val = get_value(key);
                if(!val)
                    return std::nullopt;
                try{
                    opts.demo_host_port = static_cast<uint16_t>(std::stoi(std::string(*val)));
                }
                catch(...){
                    std::cerr << "Error: Invalid demo port '" << *val << "'\n";
                    return std::nullopt;
                }
            }
            else{
                std::cerr << "Error: Unrecognized option '" << arg << "'\n\n";
                print_help(prog_name);
                return std::nullopt;
            }
        }

        return opts;
    }
};
} // namespace cli
