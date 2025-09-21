#include <array>
#include <algorithm>
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

#ifdef __linux__
#include <arpa/inet.h>
#endif

using namespace std;
using namespace dns;

namespace
{

bool looksLikeIPv4(const std::string& text)
{
    if (std::count(text.begin(), text.end(), '.') != 3)
        return false;

    size_t start = 0;
    for (int i = 0; i < 4; ++i)
    {
        size_t end = text.find('.', start);
        if (end == std::string::npos)
            end = text.size();

        if (end <= start || end - start > 3)
            return false;

        int value = 0;
        for (size_t j = start; j < end; ++j)
        {
            unsigned char c = static_cast<unsigned char>(text[j]);
            if (!std::isdigit(c))
                return false;
            value = value * 10 + (c - '0');
            if (value > 255)
                return false;
        }

        start = end + 1;
    }

    return start == text.size() + 1;
}


bool looksLikeIPv6(const std::string& text)
{
    if (text.find(':') == std::string::npos)
        return false;

    std::array<uint8_t, 16> buffer{};
    int res = inet_pton(AF_INET6, text.c_str(), buffer.data());
    return res == 1;
}


bool looksLikeDomain(const std::string& text)
{
    if (text.empty())
        return false;
    if (text.size() > 253)
        return false;
    if (text.find('.') == std::string::npos)
        return false;
    if (text.find("..") != std::string::npos)
        return false;

    size_t start = 0;
    while (start < text.size())
    {
        size_t dot = text.find('.', start);
        size_t length = (dot == std::string::npos) ? text.size() - start : dot - start;
        if (length == 0 || length > 63)
            return false;

        for (size_t i = 0; i < length; ++i)
        {
            unsigned char c = static_cast<unsigned char>(text[start + i]);
            if (!(std::isalnum(c) || c == '-'))
                return false;
        }

        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }

    return true;
}


uint16_t inferQueryType(const std::string& payload)
{
    if (looksLikeIPv4(payload))
        return 1;
    if (looksLikeIPv6(payload))
        return 28;
    if (looksLikeDomain(payload))
        return 5;
    return 16;
}

}


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

    if(!msg.empty())
        setMsg(msg);

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

    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    {
        // std::cout << "Error occurred during connection" << std::endl;
    }

    while(!m_msgQueue.empty() || m_moreMsgToGet)
    {
        std::string qname;
        uint16_t qtype = 16;

        if(!m_msgQueue.empty())
        {
            std::string subdomain = addDotEvery62Chars(m_msgQueue.front());
            qname += subdomain;
            qname += ".";
            qtype = inferQueryType(m_msgQueue.front());
            m_msgQueue.pop();
        }
        else
        {
            qname = "admin";
            qname += generateRandomString(8);
            qname += ".";
        }

        qname += m_domainToResolve;
        query.setQName(qname);
        query.setQType(qtype);
        query.setQClass(1);

        nbytes = query.code(buffer);

        int t_len = sizeof(serv_addr);
        int req = sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &serv_addr, t_len);
        if(req < 1)
        {
            // std::cout << "Error occurred during sending" << std::endl;
            break;
        }

        FD_SET(sockfd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 10;
        int selection = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        if(selection < 1)
        {
            if (selection != -1)
            {
                FD_CLR(sockfd, &read_fds);
                break;
            }
            else
            {
                // std::cout << "Error: select didn't work properly" << std::endl;
                break;
            }
        }

#ifdef __linux__
        int received = recvfrom(sockfd, &buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#elif _WIN32
        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#endif

        Response response;
        response.decode(buffer, received);

        std::string rdata = response.getRdataAsString();
        handleResponse(rdata);

        // TODO make it configurable - Resolvers usually accept ~5–20 qps per client without rate-limiting. Above that, some will throttle or blacklist.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

#ifdef __linux__
    close(sockfd);
#elif _WIN32
    closesocket(sockfd);
    WSACleanup();
#endif
}
