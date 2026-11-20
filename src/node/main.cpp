#include "src/node/cli.hpp"
#include "src/node/node.hpp"

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include "quill/sinks/FileSink.h"
#include "quill/sinks/ConsoleSink.h"


static void setup_loggers(const std::string& log_file, bool log_to_terminal){
    auto file_sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
        log_file,
        [](){
            quill::FileSinkConfig cfg;
            cfg.set_open_mode('w');
            return cfg;
        }(),
        quill::FileEventNotifier{}
    );

    std::vector<std::shared_ptr<quill::Sink>> sinks{file_sink};

    if(log_to_terminal){
        auto console_sink = quill::Frontend::create_or_get_sink<quill::ConsoleSink>("console_sink");
        sinks.push_back(console_sink);
    }

    quill::Frontend::create_or_get_logger(
        "client_logger",
        sinks,
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Client] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Frontend::create_or_get_logger(
        "relay_logger",
        sinks,
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Relay] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Frontend::create_or_get_logger(
        "exit_logger",
        sinks,
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Exit] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Frontend::create_or_get_logger(
        "main_logger",
        sinks,
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Main] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Frontend::create_or_get_logger(
        "node_logger",
        sinks,
        quill::PatternFormatterOptions{
            "[%(log_level)] [%(time)] [%(thread_id)] [Node] [%(caller_function)] [%(short_source_location)] %(message)",
            "%H:%M:%S.%Qns"
        }
    );

    quill::Backend::start();
}


int main(const int argc, char* argv[]){
    auto cli_opts = cli::CliParser::parse(argc, argv);
    if(!cli_opts){
        return 1;
    }
    if(cli_opts->show_help){
        cli::CliParser::print_help(argv[0] ? argv[0] : "node");
        return 0;
    }
    if(cli_opts->show_version){
        cli::CliParser::print_version();
        return 0;
    }

    // quill
    setup_loggers(cli_opts->log_file, cli_opts->console_log);
    auto main_logger = quill::Frontend::get_logger("main_logger");
    LOG_INFO(main_logger, "Starting node with role: {}, threads: {}, log_file: {}",
             cli::CliParser::role_to_string(cli_opts->role),
             cli_opts->thread_count,
             cli_opts->log_file);

    asio::io_context ioc;
    auto work_guard = asio::make_work_guard(ioc);

    auto cli_opts_ptr = std::make_shared<cli::CliOptions>(cli_opts.value());
    const auto node = std::make_shared<Node>(ioc, cli_opts_ptr);

    auto shutdown = [&](){
        LOG_INFO(main_logger, "Stopping node and releasing work guard.");
        asio::co_spawn(ioc, [node]() -> asio::awaitable<void> {
                           co_await node->stop();
                       },
                       asio::detached);
        work_guard.reset(); // ioc.run() to returns once remaining handlers finish

        auto force_timer = std::make_shared<asio::steady_timer>(ioc, std::chrono::seconds(10));
        force_timer->async_wait([&ioc, force_timer, main_logger](const boost::system::error_code& ec){
            if(!ec){
                LOG_WARNING(main_logger, "Graceful shutdown timed out: forcing ioc.stop().");
                ioc.stop();
            }
        });
    };

    // capture signints or sigterms (for clean exit, communicate with relays/exit, kill utun etc)
    asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& error, int /*signal_number*/){
        if(!error){
            LOG_INFO(main_logger, "Sigint/Sigterm. Stopping Initiated.");
            shutdown();
        }
    });

    asio::post(ioc, [&ioc, main_logger, node, shutdown, cli_opts_ptr](){
        LOG_INFO(main_logger, "Trying node->start().");
        asio::co_spawn(ioc, node->start(cli_opts_ptr), [main_logger, shutdown](const std::exception_ptr& e, const bool result){
            if(!e){
                if(result)
                    LOG_INFO(main_logger, "Node started.");
                else{
                    LOG_ERROR(main_logger, "Node couldn't start. Aborting.");
                    shutdown();
                }
            }
            else{
                try{
                    std::rethrow_exception(e);
                }
                catch(const std::exception& ex){
                    LOG_ERROR(main_logger, "coroutine threw exception: {}", ex.what());
                }
                shutdown();
            }
        });
    });

    // thread_pool
    const size_t thread_count = cli_opts->thread_count;
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

    LOG_INFO(main_logger, "Joining all threads.");

    for(auto& t: threads){
        if(t.joinable()){
            t.join();
        }
    }

    LOG_INFO(main_logger, "Shut down complete.");

    return 0;
}
