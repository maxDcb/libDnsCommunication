#pragma once

#include <atomic>
#include <chrono>
#include <unordered_map>

#ifdef __linux__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#elif _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#endif

#include "dns.hpp"
#include "query.hpp"
#include "response.hpp"
#include "dnsPacker.hpp"


namespace dns 
{

class Server : public Dns
{
public:

    Server(int port, const std::string& domainToResolve);
    ~Server();

    bool launch();
    void stop();
    bool isRunning() const { return !m_isStopped.load(); }
    int getPort() const { return m_port; }

    std::pair<std::string, std::string>  getAvailableMessage();
    bool setMessageToSend(const std::string& msg, const std::string& clientId);

protected:
    // Protected to allow deterministic protocol-contract tests without a UDP
    // proxy. The production entry point remains the private worker loop.
    void prepareResponse(const Query& query, Response& response);

private:
    void run();

    struct CompletedDownloadAck
    {
        std::string session;
        int index = -1;
        std::chrono::steady_clock::time_point updatedAt;
    };

    static const int BUFFER_SIZE = 4096;

    int m_port;
    struct sockaddr_in m_address{};
#ifdef _WIN32
    SOCKET m_sockfd = INVALID_SOCKET;
    bool m_wsaStarted = false;
#else
    int m_sockfd = -1;
#endif

    std::atomic<bool> m_isStopped{true};
    std::unordered_map<std::string, CompletedDownloadAck> m_completedDownloadAcks;
    
    std::unique_ptr<std::thread> m_dnsServ;
};

}


