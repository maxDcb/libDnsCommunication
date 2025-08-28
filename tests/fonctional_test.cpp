#include <iostream>
#include <string>
#include <string_view>
#include <chrono>
#include <thread>
#include <optional>
#include <cstdlib>

#include "server.hpp"
#include "client.hpp"

using namespace dns;

namespace {

void print_usage(std::ostream& os) {
    os <<
R"(fonctionalTest test harness

USAGE
  Server mode:
    fonctionalTest server --domain ns.example.com [--port 53] [--test-msg "text"] [--run-seconds 5]

  Client mode:
    fonctionalTest client --dns 8.8.8.8 --host ns.example.com --send "text"
                     [--timeout 5] [--expect "expected-reply"]

OPTIONS
  --domain <fqdn>        (server) Authoritative domain to handle.
  --port <1-65535>       (server) UDP/TCP port for the DNS server. Default: 53
  --test-msg <text>      (server) Message the server will expose via setMsg().

  --dns <ip>             (client) DNS resolver IP to query (e.g., 8.8.8.8).
  --host <fqdn>          (client) Target host / domain to use.
  --send <text>          (client) Payload to send via Client::sendMessage().

  --timeout <seconds>    (client) How long to poll getMsg() before giving up.
                         Default: 5 seconds.
  --expect <text>        (client) If set, the test passes only if any received
                         message equals this exact string.

  --run-seconds <n>      (server) Run for N seconds then exit (useful for CI).
                         Default: 5 seconds if provided without a value.
  -h, --help             Show this help and exit.

EXIT CODES
  0  success / test passed
  1  runtime error or test failed (mismatch/timeout)
  2  invalid arguments
)";
}

bool parse_int(const std::string& s, int& out) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc <= 1) {
        print_usage(std::cerr);
        return 2;
    }

    std::string mode = argv[1];
    if (mode == "-h" || mode == "--help") {
        print_usage(std::cout);
        return 0;
    }

    // Simple flag parser (order-insensitive, no external deps)
    auto get_arg = [&](int i) -> std::string_view { return std::string_view(argv[i]); };

    // Common parameters
    int port = 53;
    std::string domain;
    std::optional<std::string> server_test_msg;
    std::optional<int> server_run_seconds;

    std::string dns_ip;
    std::string host;
    std::optional<std::string> client_send;
    int client_timeout_sec = 5;
    std::optional<std::string> expect_eq;

    // Parse flags starting from argv[2]
    for (int i = 2; i < argc; ++i) {
        std::string_view a = get_arg(i);

        auto need_value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                std::cerr << "Use --help for usage.\n";
                std::exit(2);
            }
            return std::string(get_arg(++i));
        };

        if (a == "--domain")        { domain = need_value("--domain"); }
        else if (a == "--port")     {
            std::string v = need_value("--port");
            if (!parse_int(v, port) || port < 1 || port > 65535) {
                std::cerr << "Invalid --port: " << v << "\n";
                return 2;
            }
        }
        else if (a == "--test-msg") { server_test_msg = need_value("--test-msg"); }
        else if (a == "--run-seconds") {
            std::string v = need_value("--run-seconds");
            int s = 0;
            if (!parse_int(v, s) || s <= 0) {
                std::cerr << "Invalid --run-seconds: " << v << "\n";
                return 2;
            }
            server_run_seconds = s;
        }
        else if (a == "--dns")      { dns_ip = need_value("--dns"); }
        else if (a == "--host")     { host = need_value("--host"); }
        else if (a == "--send")     { client_send = need_value("--send"); }
        else if (a == "--timeout")  {
            std::string v = need_value("--timeout");
            if (!parse_int(v, client_timeout_sec) || client_timeout_sec <= 0) {
                std::cerr << "Invalid --timeout: " << v << "\n";
                return 2;
            }
        }
        else if (a == "--expect")   { expect_eq = need_value("--expect"); }
        else if (a == "-h" || a == "--help") {
            print_usage(std::cout);
            return 0;
        }
        else {
            std::cerr << "Unknown argument: " << a << "\n";
            std::cerr << "Use --help for usage.\n";
            return 2;
        }
    }

    try {
        if (mode == "server") {
            if (domain.empty()) {
                std::cerr << "Missing required --domain for server mode.\n";
                return 2;
            }

            Server server(port, domain);

            // If not provided, default to a stable test message to make CI deterministic.
            const std::string default_msg =
                "elevator puzzle umbrella sparkle facade galaxy misty blossom horizon "
                "thunder kitten embrace wanderer velvet whisper journey melody prism "
                "twilight harmony radiant tranquility paradise reflection serendipity "
                "breeze blossom moonlight tranquility radiant whisper serendipity horizon";

            server.launch();
            server.setMsg(server_test_msg.value_or(default_msg));

            // Run for a bounded time (default to 5s if --run-seconds passed without value; here we require value)
            const int run_secs = server_run_seconds.value_or(5);
            auto end = std::chrono::steady_clock::now() + std::chrono::seconds(run_secs);

            while (std::chrono::steady_clock::now() < end) {
                std::string result = server.getMsg();
                if (!result.empty()) {
                    std::cout << "[server] msg: " << result << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            server.stop();
            return 0;
        }
        else if (mode == "client") {
            if (dns_ip.empty() || host.empty() || !client_send.has_value()) {
                std::cerr << "Missing required flags for client mode. Need --dns, --host, --send.\n";
                return 2;
            }

            Client client(dns_ip, host, port);
            client.sendMessage(*client_send);

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(client_timeout_sec);
            bool matched = !expect_eq.has_value(); // if no expectation, success if we get anything (or just complete)

            while (std::chrono::steady_clock::now() < deadline) {
                std::string result = client.getMsg();
                if (!result.empty()) {
                    std::cout << "[client] msg: " << result << std::endl;
                    if (expect_eq && result == *expect_eq) {
                        matched = true;
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (expect_eq) {
                if (!matched) {
                    std::cerr << "[client] EXPECTATION FAILED: did not receive expected message within "
                              << client_timeout_sec << "s\nExpected: \"" << *expect_eq << "\"\n";
                    return 1;
                }
                std::cout << "[client] EXPECTATION OK\n";
            }

            return matched ? 0 : 0; // treat as success if no --expect
        }
        else {
            std::cerr << "First argument must be 'server' or 'client'.\n";
            std::cerr << "Use --help for usage.\n";
            return 2;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unhandled unknown exception\n";
        return 1;
    }
}
