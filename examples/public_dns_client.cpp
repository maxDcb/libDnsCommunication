#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef __linux__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#elif _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "query.hpp"
#include "response.hpp"

namespace
{

uint16_t parse_type(const std::string& value)
{
    if (value == "A") return 1;
    if (value == "NS") return 2;
    if (value == "CNAME") return 5;
    if (value == "SOA") return 6;
    if (value == "PTR") return 12;
    if (value == "MX") return 15;
    if (value == "TXT") return 16;
    if (value == "AAAA") return 28;
    if (value == "SRV") return 33;
    try
    {
        int parsed = std::stoi(value);
        if (parsed < 0 || parsed > 65535)
            throw std::out_of_range("type out of range");
        return static_cast<uint16_t>(parsed);
    }
    catch (...)
    {
        throw std::invalid_argument("Unsupported RR type '" + value + "'");
    }
}

void print_usage()
{
    std::cerr << "Usage: public_dns_client <resolver-ip> <name> [type]" << std::endl;
    std::cerr << "Example: public_dns_client 8.8.8.8 example.com TXT" << std::endl;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        print_usage();
        return 1;
    }

    const std::string resolver = argv[1];
    const std::string qname = argv[2];
    const std::string typeStr = (argc >= 4) ? argv[3] : std::string("TXT");

    uint16_t qtype = 16;
    try
    {
        qtype = parse_type(typeStr);
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
#endif

#ifdef _WIN32
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = -1;
#endif
    try
    {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
        if (sock == INVALID_SOCKET)
            throw std::runtime_error("socket() failed");
#else
        if (sock < 0)
            throw std::runtime_error("socket() failed");
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
#ifdef __linux__
        if (inet_pton(AF_INET, resolver.c_str(), &addr.sin_addr) != 1)
            throw std::runtime_error("inet_pton failed for resolver");
#elif _WIN32
        if (InetPtonA(AF_INET, resolver.c_str(), &addr.sin_addr) != 1)
            throw std::runtime_error("InetPton failed for resolver");
#endif

        dns::Query query;
        auto nowTicks = static_cast<uint16_t>(std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFF);
        query.setID(nowTicks);
        query.setQName(qname);
        query.setQType(qtype);
        query.setQClass(1);
        query.setQdCount(1);
        query.setAnCount(0);
        query.setNsCount(0);
        query.setArCount(0);

        std::string wire = query.encode();
        const int qlen = static_cast<int>(wire.size());

        int sent = sendto(sock, wire.data(), qlen, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#ifdef _WIN32
        if (sent == SOCKET_ERROR)
            throw std::runtime_error("sendto() failed");
#else
        if (sent != qlen)
            throw std::runtime_error("sendto() failed");
#endif

        char recvBuf[1024];
#ifdef __linux__
        const int received = recvfrom(sock, recvBuf, sizeof(recvBuf), 0, nullptr, nullptr);
#elif _WIN32
        int addrLen = sizeof(addr);
        const int received = recvfrom(sock, recvBuf, sizeof(recvBuf), 0, reinterpret_cast<sockaddr*>(&addr), &addrLen);
#endif
        if (received <= 0)
            throw std::runtime_error("recvfrom() failed");

        dns::Response response;
        response.decode(recvBuf, received);

        std::cout << "Response ID: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << response.getID() << std::dec << std::setfill(' ') << std::endl;
        std::cout << "Question: " << response.getQuestionName() << std::endl;
        std::cout << "Answer name: " << response.getName() << std::endl;
        std::cout << "RDATA (text): " << response.getRdata() << std::endl;

        const auto& raw = response.getRdataBytes();
        if (!raw.empty())
        {
            std::cout << "RDATA (hex):";
            for (auto byte : raw)
                std::cout << ' ' << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(byte);
            std::cout << std::dec << std::setfill(' ') << std::endl;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
        if (
#ifdef _WIN32
            sock != INVALID_SOCKET
#else
            sock >= 0
#endif
        )
        {
#ifdef __linux__
            close(sock);
#elif _WIN32
            closesocket(sock);
#endif
        }
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (
#ifdef _WIN32
        sock != INVALID_SOCKET
#else
        sock >= 0
#endif
    )
    {
#ifdef __linux__
        close(sock);
#elif _WIN32
        closesocket(sock);
#endif
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
