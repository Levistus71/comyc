#include "src/node/node.hpp"

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include "quill/sinks/FileSink.h"
#include <quill/LogMacros.h>


static void setup_loggers(){
    auto file_sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
        "logs.txt",
        [](){
            quill::FileSinkConfig cfg;
            cfg.set_open_mode('w');
            return cfg;
        }(),
        quill::FileEventNotifier{}
    );

    quill::Frontend::create_or_get_logger(
        "client_logger",
        std::move(file_sink),
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Client] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    file_sink = quill::Frontend::get_sink("logs.txt");
    quill::Frontend::create_or_get_logger(
        "relay_logger",
        std::move(file_sink),
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Relay] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    file_sink = quill::Frontend::get_sink("logs.txt");
    quill::Frontend::create_or_get_logger(
        "exit_logger",
        std::move(file_sink),
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Exit] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    file_sink = quill::Frontend::get_sink("logs.txt");
    quill::Frontend::create_or_get_logger(
        "main_logger",
        std::move(file_sink),
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Main] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    file_sink = quill::Frontend::get_sink("logs.txt");
    quill::Frontend::create_or_get_logger(
        "node_logger",
        std::move(file_sink),
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Node] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Backend::start();
}


int main(){
    // quill
    setup_loggers();
    auto main_logger = quill::Frontend::get_logger("main_logger");

    asio::io_context ioc;
    auto work_guard = asio::make_work_guard(ioc);

    // fixme: role should be decided dynamically
    constexpr auto role = NodeRole::CLIENT_RELAY;
    const auto node = std::make_shared<Node>(ioc, role);
    LOG_INFO(main_logger, "Trying node->start().");
    if(!node->start()){
        LOG_ERROR(main_logger, "Node couldn't start. Aborting.");
        return 1;
    }
    LOG_INFO(main_logger, "Node started.");

    // capture signints or sigterms (for clean exit, communicate with relays/exit, kill utun etc)
    asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& error, int /*signal_number*/){
        if(!error){
            LOG_INFO(main_logger, "Sigint/Sigterm. Stopping Initiated.");
            node->stop();
            work_guard.reset();
            ioc.stop();
        }
    });

    // thread_pool
    const size_t thread_count = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1);

    for(size_t i = 0; i < thread_count - 1; i++){
        threads.emplace_back([&ioc](){
            ioc.run();
        });
    }

    // last thread on main
    ioc.run();
    // code from this line runs after signals.async_wait calls work_guard.reset();

    for(auto& t: threads){
        if(t.joinable()){
            t.join();
        }
    }

    LOG_INFO(main_logger, "Shut down complete.");

    return 0;
}
