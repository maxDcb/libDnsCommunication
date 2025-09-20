#include <iostream>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <string_view>
#include <errno.h>
#ifdef __linux__
#include <unistd.h>
#elif _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "client.hpp"
#include "debugLog.hpp"

using namespace std;
using namespace dns;

Client::Client(const std::string& dnsServerAdd, const std::string& domainToResolve, int port)
: Dns(domainToResolve)
, m_dnsServerAdd(dnsServerAdd)
, m_port(port)
{}

Client::~Client()
{
}

void Client::sendMessage(const std::string& msg)
{
    char buffer[BUFFER_SIZE];
    int nbytes = 0;

    Query query;
    query.setID(0);
    query.setQdCount(1);
    query.setAnCount(0);
    query.setNsCount(0);
    query.setArCount(0);

    dns::debug::log(
        "Client::sendMessage",
        "Preparing transmission to DNS server " + m_dnsServerAdd + ":" +
            std::to_string(m_port));

    if(!msg.empty())
    {
        dns::debug::log(
            "Client::sendMessage",
            "Queueing new payload of " +
                std::to_string(static_cast<unsigned long long>(msg.size())) +
                " bytes");
        setMsg(msg);
    }
    else
    {
        dns::debug::log("Client::sendMessage",
                        "No new payload provided; sending queued fragments");
    }

    dns::debug::log(
        "Client::sendMessage",
        "Outbound fragment queue contains " +
            std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) +
            " item(s); awaiting more fragments=" +
            (m_moreMsgToGet ? std::string("true") : std::string("false")));

    struct sockaddr_in serv_addr;
    fd_set read_fds;
    FD_ZERO(&read_fds);

#ifdef __linux__
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    inet_aton(m_dnsServerAdd.c_str(), &(serv_addr.sin_addr));
#elif _WIN32
    WSAData data;
    WSAStartup(MAKEWORD(2, 2), &data);
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr( m_dnsServerAdd.c_str() );
#endif

    dns::debug::log("Client::sendMessage",
                    "UDP socket created; attempting connection test via connect()");

    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    {
        dns::debug::log("Client::sendMessage",
                        "connect() failed; continuing with sendto/recvfrom");
    }
    else
    {
        dns::debug::log("Client::sendMessage",
                        "connect() succeeded for diagnostic connection check");
    }

    size_t iteration = 0;
    auto sessionStart = std::chrono::steady_clock::now();
    while(!m_msgQueue.empty() || m_moreMsgToGet)
    {
        ++iteration;
        auto iterationStart = std::chrono::steady_clock::now();
        dns::debug::log(
            "Client::sendMessage",
            "Iteration " + std::to_string(iteration) +
                ": fragments remaining before dequeue=" +
                std::to_string(
                    static_cast<unsigned long long>(m_msgQueue.size())) +
                ", awaiting more=" +
                (m_moreMsgToGet ? std::string("true") : std::string("false")));

        std::string qname;
        if(!m_msgQueue.empty())
        {
            const std::string fragmentHex = m_msgQueue.front();
            std::string preview = fragmentHex.substr(0, 60);
            if(fragmentHex.size() > preview.size())
                preview += "...";

            std::string subdomain = addDotEvery62Chars(fragmentHex);
            qname += subdomain;
            qname += ".";
            m_msgQueue.pop();

            dns::debug::log(
                "Client::sendMessage",
                "Dequeued fragment hex-length=" +
                    std::to_string(
                        static_cast<unsigned long long>(fragmentHex.size())) +
                    " preview='" + preview + "'");
        }
        else
        {
            qname = "admin";
            qname += generateRandomString(8);
            qname += ".";

            dns::debug::log("Client::sendMessage",
                            "No fragment ready; issuing keep-alive query '" +
                                qname + "'");
        }

        qname += m_domainToResolve;
        query.setQName(qname);
        query.setQType(16);
        query.setQClass(1);

        nbytes = query.code(buffer);

        dns::debug::log(
            "Client::sendMessage",
            "Encoded query length=" + std::to_string(nbytes) +
                " bytes for QNAME '" + qname + "'");

        int t_len = sizeof(serv_addr);
        int req = sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &serv_addr, t_len);
        if(req < 1)
        {
            dns::debug::log("Client::sendMessage",
                            "sendto() failed with return value " +
                                std::to_string(req));
            break;
        }

        auto afterSend = std::chrono::steady_clock::now();
        dns::debug::log(
            "Client::sendMessage",
            "Sent " + std::to_string(req) + " bytes to " + m_dnsServerAdd +
                ":" + std::to_string(m_port) + " (" +
                dns::debug::formatDuration(afterSend - iterationStart) +
                " since iteration start)");

        FD_SET(sockfd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 10;
        int selection = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        auto afterSelect = std::chrono::steady_clock::now();

        if(selection < 1)
        {
            if (selection != -1)
            {
                FD_CLR(sockfd, &read_fds);
                dns::debug::log(
                    "Client::sendMessage",
                    "select() timeout after " +
                        dns::debug::formatDuration(afterSelect - afterSend));
                break;
            }
            else
            {
                dns::debug::log("Client::sendMessage",
                                "select() returned error after " +
                                    dns::debug::formatDuration(afterSelect -
                                                               afterSend));
                break;
            }
        }

#ifdef __linux__
        int received = recvfrom(sockfd, &buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#elif _WIN32
        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#endif

        auto afterRecv = std::chrono::steady_clock::now();

        dns::debug::log(
            "Client::sendMessage",
            "recvfrom() returned " + std::to_string(received) +
                " bytes after " +
                dns::debug::formatDuration(afterRecv - afterSend));

        Response response;
        response.decode(buffer, received);

        std::string rdata = response.getRdata();

        std::string rdataPreview = rdata.substr(0, 60);
        if(rdata.size() > rdataPreview.size())
            rdataPreview += "...";
        dns::debug::log(
            "Client::sendMessage",
            "Received RDATA length=" +
                std::to_string(static_cast<unsigned long long>(rdata.size())) +
                " preview='" + rdataPreview + "'");

        handleResponse(rdata);

        auto afterHandle = std::chrono::steady_clock::now();
        dns::debug::log(
            "Client::sendMessage",
            "Response handling completed in " +
                dns::debug::formatDuration(afterHandle - afterRecv) +
                "; fragments remaining=" +
                std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) +
                ", awaiting more=" +
                (m_moreMsgToGet ? std::string("true") : std::string("false")));

        dns::debug::log("Client::sendMessage",
                        "Applying inter-query delay of 1000 ms to avoid flooding");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        dns::debug::log(
            "Client::sendMessage",
            "Iteration " + std::to_string(iteration) + " total time " +
                dns::debug::formatDuration(std::chrono::steady_clock::now() -
                                           iterationStart));
    }

    dns::debug::log(
        "Client::sendMessage",
        "Transmission loop completed after " +
            dns::debug::formatDuration(std::chrono::steady_clock::now() -
                                       sessionStart) +
            "; remaining fragments=" +
            std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) +
            ", awaiting more=" +
            (m_moreMsgToGet ? std::string("true") : std::string("false")));

#ifdef __linux__
    close(sockfd);
#elif _WIN32
    closesocket(sockfd);
    WSACleanup();
#endif

    dns::debug::log("Client::sendMessage", "Socket closed");
}
