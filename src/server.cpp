#include <array>
#include <cstring>
#include <optional>
#include <vector>

#include <algorithm>
#include <cctype>
#include <string_view>

#include <errno.h>

#include "server.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

using namespace std;
using namespace dns;

namespace
{

bool parseIPv4Address(const std::string& text, std::vector<uint8_t>& out)
{
    out.clear();
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

        out.push_back(static_cast<uint8_t>(value));
        start = end + 1;
    }

    return out.size() == 4 && start == text.size() + 1;
}


bool parseIPv6Address(const std::string& text, std::vector<uint8_t>& out)
{
    out.clear();
    if (text.find(':') == std::string::npos)
        return false;

    std::array<uint8_t, 16> buffer{};
    int res = inet_pton(AF_INET6, text.c_str(), buffer.data());
    if (res != 1)
        return false;

    out.assign(buffer.begin(), buffer.end());
    return true;
}


bool looksLikeDomainName(const std::string& text)
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


std::optional<uint16_t> parsePreference(const std::string& text)
{
    if (text.empty())
        return std::nullopt;

    unsigned long value = 0;
    for (char c : text)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!std::isdigit(uc))
            return std::nullopt;
        value = value * 10 + (uc - '0');
        if (value > 65535)
            return std::nullopt;
    }

    return static_cast<uint16_t>(value);
}

}


Server::Server(int port, const std::string& domainToResolve)
: Dns(domainToResolve)
, m_port(port)
{ 

}


Server::~Server()
{
    stop();
}


void Server::stop()
{
    if (m_isStoped)
        return;
    m_isStoped=true;
    // Send an empty datagram to unblock recvfrom
    struct sockaddr_in addr = m_address;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char byte = 0;
    sendto(m_sockfd, &byte, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    if(m_dnsServ && m_dnsServ->joinable())
        m_dnsServ->join();
#ifdef __linux__
    close(m_sockfd);
#elif _WIN32
    closesocket(m_sockfd);
    WSACleanup();
#endif
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

    m_isStoped=false;
    m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(m_port);

    int rbind = bind(m_sockfd, (struct sockaddr *) & m_address, sizeof(struct sockaddr_in));
    if (rbind != 0) 
    {
        string text("Could not bind: ");
        text += strerror(errno);

#ifdef _WIN32
        WSACleanup();
#endif

        return;
    }

    this->m_dnsServ = std::make_unique<std::thread>(&Server::run, this);
}


void Server::run()
{    
    char buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);

    while(!m_isStoped) 
    {
        int nbytes = recvfrom(m_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);

        Query query;
        query.decode(buffer, nbytes);

        std::string qname = query.getQName();
        addReceivedQName(qname);

        Response response;
        handleQuery(query, response);

        memset(buffer, 0, BUFFER_SIZE);
        nbytes = response.code(buffer);

        sendto(m_sockfd, buffer, nbytes, 0, (struct sockaddr *) &clientAddress, addrLen);
    }
}


void Server::handleQuery(const Query& query, Response& response)
{
    string qName = query.getQName();

    string domainName = "";
    if (endsWith(qName, m_domainToResolve))
    {
        if(!m_msgQueue.empty())
        {
            domainName = m_msgQueue.front();
            m_msgQueue.pop();
        }
        else
        {
            domainName = "admin";
            domainName += generateRandomString(8);
        }
    }

    // std::cout << "domainName " << domainName << std::endl;
    
    response.setID(query.getID());
    response.setName(query.getQName());
    response.setClass(query.getQClass());
    response.setType(query.getQType());
    response.setQdCount(1);
    response.setAnCount(0);
    response.setNsCount(0);
    response.setArCount(0);
    response.clearRdata();

    if (domainName.empty())
    {
        response.setRCode(Response::NameError);
        return;
    }

    uint16_t qType = query.getQType();
    bool rdataSet = false;

    switch (qType)
    {
        case 1:
        {
            std::vector<uint8_t> bytes;
            if (parseIPv4Address(domainName, bytes))
            {
                response.setAddressRdata(bytes);
                rdataSet = true;
            }
            break;
        }
        case 28:
        {
            std::vector<uint8_t> bytes;
            if (parseIPv6Address(domainName, bytes))
            {
                response.setAddressRdata(bytes);
                rdataSet = true;
            }
            break;
        }
        case 5:
        {
            if (looksLikeDomainName(domainName))
            {
                response.setDomainRdata(domainName);
                rdataSet = true;
            }
            break;
        }
        case 15:
        {
            std::string host = domainName;
            std::optional<uint16_t> preference;
            size_t spacePos = domainName.find(' ');
            if (spacePos != std::string::npos)
            {
                preference = parsePreference(domainName.substr(0, spacePos));
                host = domainName.substr(spacePos + 1);
            }

            if (looksLikeDomainName(host))
            {
                Response::DomainRdata mx{host, preference};
                response.setDomainRdata(mx);
                rdataSet = true;
            }
            break;
        }
        case 16:
        {
            response.setTxtRdata(domainName);
            rdataSet = true;
            break;
        }
        default:
            break;
    }

    if (rdataSet)
    {
        response.setRCode(Response::Ok);
        response.setAnCount(1);
    }
    else
    {
        response.setRCode(Response::ServerFailure);
        response.clearRdata();
    }
}