
#pragma once

#include <iostream>
#include <queue>
#include <vector>

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

class Client : public Dns
{
public:

    Client(const std::string& dnsServerAdd, const std::string& domainToResolve, int port = 53);
    ~Client();

    void sendMessage(const std::string& msg);
    
private:
    static const int BUFFER_SIZE = 1024;

    struct sockaddr_in m_address;
    int m_sockfd;

    std::string m_dnsServerAdd;
    int m_port;
};

}



