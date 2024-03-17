#pragma once

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

    void launch();
    void stop();

private:
    void run();

    void handleQuery(const Query& query, Response& response);

    static const int BUFFER_SIZE = 1024;

    int m_port;
    struct sockaddr_in m_address;
    int m_sockfd;    

    bool m_isStoped;
    
    std::unique_ptr<std::thread> m_dnsServ;
};

}


