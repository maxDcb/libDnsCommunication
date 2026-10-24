#include <iostream>
#include <cstring>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <string_view>
#include <vector>

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
struct ParsedClientName
{
    std::string clientId;
    std::string data;
    std::vector<std::string> labels;
};

std::vector<std::string> splitLabels(const std::string& value)
{
    std::vector<std::string> labels;
    size_t start = 0;
    while (start <= value.size())
    {
        const size_t dot = value.find('.', start);
        const size_t end = dot == std::string::npos ? value.size() : dot;
        if (end == start)
            return {};
        labels.push_back(value.substr(start, end - start));
        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }
    return labels;
}

bool parseClientName(const std::string& qname,
                     const std::string& domain,
                     ParsedClientName& parsed)
{
    if (domain.empty() || qname.size() <= domain.size() + 1)
        return false;

    const size_t domainOffset = qname.size() - domain.size();
    if (qname[domainOffset - 1] != '.' ||
        dns::str_tolower(qname.substr(domainOffset)) != dns::str_tolower(domain))
        return false;

    const std::string prefix = qname.substr(0, domainOffset - 1);
    const size_t idSeparator = prefix.rfind('.');
    if (idSeparator == std::string::npos)
        return false;

    parsed.data = prefix.substr(0, idSeparator);
    parsed.clientId = dns::str_tolower(prefix.substr(idSeparator + 1));
    parsed.labels = splitLabels(parsed.data);

    if (parsed.data.empty() || parsed.labels.empty() ||
        parsed.clientId.empty() || parsed.clientId.size() > 32 ||
        !std::all_of(parsed.clientId.begin(), parsed.clientId.end(), [](unsigned char c) {
            return std::isalnum(c) != 0;
        }))
        return false;
    return true;
}

bool parseNonNegativeInt(const std::string& value, int& result)
{
    result = -1;
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto parsed = std::from_chars(begin, end, result);
    return parsed.ec == std::errc{} && parsed.ptr == end && result >= 0;
}

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
: Dns(domainToResolve, "")
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
    const bool wasStopped = m_isStopped.exchange(true);

    if (!wasStopped)
    {
        dns::debug::log("Server::stop",
                        "Stopping server on port " + std::to_string(m_port));
        struct sockaddr_in addr = m_address;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        char byte = 0;
#ifdef _WIN32
        if (m_sockfd != INVALID_SOCKET)
#else
        if (m_sockfd >= 0)
#endif
            sendto(m_sockfd, &byte, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    }

    if(m_dnsServ && m_dnsServ->joinable())
    {
        dns::debug::log("Server::stop", "Joining worker thread");
        m_dnsServ->join();
    }
#ifdef __linux__
    if (m_sockfd >= 0)
    {
        close(m_sockfd);
        m_sockfd = -1;
    }
#elif _WIN32
    if (m_sockfd != INVALID_SOCKET)
    {
        closesocket(m_sockfd);
        m_sockfd = INVALID_SOCKET;
    }
    if (m_wsaStarted)
    {
        WSACleanup();
        m_wsaStarted = false;
    }
#endif
    m_dnsServ.reset();
}


bool Server::launch()
{
    if (!m_isStopped.load())
        return true;

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        return false;
    }
    m_wsaStarted = true;
#endif

    dns::debug::log("Server::launch",
                    "Launching server for domain '" + m_domainToResolve +
                        "' on port " + std::to_string(m_port));

    m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

#ifdef _WIN32
    if(m_sockfd == INVALID_SOCKET)
#else
    if(m_sockfd < 0)
#endif
    {
        dns::debug::log("Server::launch",
                        "socket() failed: " + std::string(strerror(errno)));
#ifdef _WIN32
        WSACleanup();
        m_wsaStarted = false;
#endif
        return false;
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
        closesocket(m_sockfd);
        m_sockfd = INVALID_SOCKET;
        WSACleanup();
        m_wsaStarted = false;
#else
        close(m_sockfd);
        m_sockfd = -1;
#endif

        return false;
    }

    if (m_port == 0)
    {
        socklen_t addressLength = sizeof(m_address);
        if (getsockname(m_sockfd,
                        reinterpret_cast<struct sockaddr*>(&m_address),
                        &addressLength) != 0)
        {
            stop();
            return false;
        }
        m_port = ntohs(m_address.sin_port);
    }

    dns::debug::log("Server::launch",
                    "Socket bound to port " + std::to_string(m_port));

    m_isStopped.store(false);
    try
    {
        this->m_dnsServ = std::make_unique<std::thread>(&Server::run, this);
    }
    catch (...)
    {
        m_isStopped.store(true);
#ifdef _WIN32
        closesocket(m_sockfd);
        m_sockfd = INVALID_SOCKET;
        WSACleanup();
        m_wsaStarted = false;
#else
        close(m_sockfd);
        m_sockfd = -1;
#endif
        return false;
    }
    dns::debug::log("Server::launch", "Worker thread started");
    return true;
}


/** Return the next complete upload assembled synchronously by the UDP worker. */
std::pair<std::string, std::string> Server::getAvailableMessage()
{
    cleanupExpiredState();
    return getMsg();
}


bool Server::setMessageToSend(const std::string& msg, const std::string& clientId)
{
    return setMsg(msg, clientId);
}

/** Receive, validate and answer DNS datagrams until stop() is requested. */

void Server::run()
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);

    dns::debug::log("Server::run", "Worker loop started");

    while(!m_isStopped.load())
    {
        try
        {
            addrLen = sizeof(struct sockaddr_in);
            auto waitStart = std::chrono::steady_clock::now();
            int nbytes = recvfrom(m_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);
            auto afterRecv = std::chrono::steady_clock::now();

        if(nbytes <= 0)
        {
            if(m_isStopped.load())
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

        if (m_isStopped.load())
            break;

        std::string clientEndpoint = endpointToString(clientAddress);
        dns::debug::log(
            "Server::run",
            "Received " + std::to_string(nbytes) + " bytes from " +
                clientEndpoint + " after " +
                dns::debug::formatDuration(afterRecv - waitStart));

        Query query;
        query.decode(buffer, nbytes);

        if (!query.isValid())
        {
            dns::debug::log("Server::run", "Discarding malformed DNS query");
            continue;
        }

        std::string qname = query.getQName();

        dns::debug::log(
            "Server::run",
            "Decoded query id=" + std::to_string(query.getID()) + " qname='" +
                qname + "' qtype=" + std::to_string(query.getQType()) +
                " qclass=" + std::to_string(query.getQClass()));

        Response response;
        auto handleStart = std::chrono::steady_clock::now();

        prepareResponse(query, response);
        
        auto afterHandle = std::chrono::steady_clock::now();

        size_t pendingQueues = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pendingQueues = m_msgQueue.size();
        }

        dns::debug::log(
            "Server::run",
            "prepareResponse completed in " +
                dns::debug::formatDuration(afterHandle - handleStart) +
                "; outbound fragment queue size=" +
                std::to_string(static_cast<unsigned long long>(pendingQueues)));

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
        catch (...)
        {
            if (m_isStopped.load())
                break;
        }
    }

    dns::debug::log("Server::run", "Worker loop terminated");
}

/**
 * Validate the domain, class and exact control labels, ingest uploads, and
 * serve one retained download fragment. A fragment is removed only when the
 * next request acknowledges its session and index.
 */

void Server::prepareResponse(const Query& query, Response& response)
{
    const string qName = query.getQName();
    string dataToSend;
    Response::Code failureCode = Response::NameError;

    const auto ackCutoff = std::chrono::steady_clock::now() - std::chrono::minutes(5);
    for (auto it = m_completedDownloadAcks.begin();
         it != m_completedDownloadAcks.end(); )
    {
        if (it->second.updatedAt < ackCutoff)
            it = m_completedDownloadAcks.erase(it);
        else
            ++it;
    }

    ParsedClientName parsed;
    if (query.getQClass() == 1 && parseClientName(qName, m_domainToResolve, parsed))
    {
        const std::string control = str_tolower(parsed.labels.front());

        if (control == m_secretKeyClientAskData && query.getQType() == 16)
        {
            bool validAsk = false;
            bool completedAcknowledgedMessage = false;
            if (parsed.labels.size() == 4)
            {
                int acknowledgedIndex = -1;
                const std::string acknowledgedSession = str_tolower(parsed.labels[1]);
                validAsk = parseNonNegativeInt(parsed.labels[2], acknowledgedIndex);
                if (validAsk && acknowledgedSession == "none")
                {
                    m_completedDownloadAcks.erase(parsed.clientId);
                }
                else if (validAsk)
                {
                    const auto completed = m_completedDownloadAcks.find(parsed.clientId);
                    if (completed != m_completedDownloadAcks.end() &&
                        completed->second.session == acknowledgedSession &&
                        completed->second.index == acknowledgedIndex)
                    {
                        completed->second.updatedAt = std::chrono::steady_clock::now();
                        completedAcknowledgedMessage = true;
                    }
                    else
                    {
                        const auto queuedIdentity = queuedFragmentIdentity(parsed.clientId);
                        const bool wasFinalFragment = queuedIdentity &&
                            queuedIdentity->session == acknowledgedSession &&
                            queuedIdentity->index == acknowledgedIndex &&
                            queuedIdentity->index + 1 == queuedIdentity->count;
                        const bool acknowledged = acknowledgeQueuedFragment(
                            parsed.clientId, acknowledgedSession, acknowledgedIndex);
                        completedAcknowledgedMessage = acknowledged && wasFinalFragment;
                        if (completedAcknowledgedMessage)
                        {
                            m_completedDownloadAcks[parsed.clientId] = {
                                acknowledgedSession,
                                acknowledgedIndex,
                                std::chrono::steady_clock::now()};
                        }
                    }
                }
            }

            if (validAsk)
            {
                if (!completedAcknowledgedMessage)
                {
                    splitPacket(query.getQType(), parsed.clientId);
                    dataToSend = peekQueuedFragment(parsed.clientId);
                }
                if (dataToSend.empty())
                    dataToSend = m_secretKeyServerNoData;
            }
            else
            {
                failureCode = Response::FormatError;
            }
        }
        else if (control == m_secretKeyClientKeepAlive &&
                 parsed.labels.size() == 2 && query.getQType() == 5)
        {
            dataToSend = m_secretKeyServerKeepAlive;
        }
        else if (query.getQType() == 5 && handleDataReceived(parsed.data, parsed.clientId))
        {
            dataToSend = m_secretKeyAck;
        }
        else
        {
            failureCode = Response::FormatError;
        }
    }

    response.setID(query.getID());
    response.setRecursionDesired(query.isRecursionDesired());
    response.setName(query.getQName());
    response.setType(query.getQType());
    response.setClass(query.getQClass());
    response.setTtl(0);
    response.setQdCount(1);
    response.setNsCount(0);
    response.setArCount(0);

    if (dataToSend.empty())
    {
        dns::debug::log("Server::prepareResponse", "Domain '" + qName + "' not in scope; sending NameError");

        response.clearAnswer();
        response.setAnCount(0);
        response.setRCode(failureCode);
    }
    else
    {
        dns::debug::log("Server::prepareResponse", "Responding with payload '" + dataToSend + "' (" + std::to_string(static_cast<unsigned long long>(dataToSend.size())) + " bytes)");

        response.setAnCount(1);
        response.setRCode(Response::Ok);
        response.setMxPreference(0);

        switch (query.getQType())
        {
            case 1: // A
            {
                std::string hex = dataToSend;
                if (hex.size() < 8)
                    hex.append(8 - hex.size(), '0');
                if (hex.size() > 8)
                    hex.resize(8);
                response.setRdata(hex);
                break;
            }
            case 28: // AAAA
            {
                std::string hex = dataToSend;
                if (hex.size() < 32)
                    hex.append(32 - hex.size(), '0');
                if (hex.size() > 32)
                    hex.resize(32);
                response.setRdata(hex);
                break;
            }
            case 15: // MX
                response.setRdata(dataToSend);
                break;
            case 5:  // CNAME
            case 2:  // NS
            case 12: // PTR
                response.setRdata(dataToSend);
                break;
            case 16: // TXT
            default:
                response.setRdata(dataToSend);
                break;
        }
    }
}



