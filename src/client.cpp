#include <iostream>
#include <cstring>
#include <string>

#include <algorithm>
#include <cctype>
#include <string_view>

#include <errno.h>

#include "client.hpp"


#ifdef __linux__

#elif _WIN32

#pragma comment(lib, "ws2_32.lib")

#endif


using namespace std;
using namespace dns;


Client::Client(const std::string& dnsServerAdd, const std::string& domainToResolve)
: Dns(domainToResolve)
, m_dnsServerAdd(dnsServerAdd)
{ 

}


Client::~Client() 
{ 
}


void Client::sendMessage(const std::string& msg)
{
    
    char buffer[BUFFER_SIZE];
    int nbytes=0;

    Query query;
    query.setID(0);
    query.setQdCount(1);
    query.setAnCount(0);
    query.setNsCount(0);
    query.setArCount(0);

    if(!msg.empty())
        setMsg(msg);

    while(!m_msgQueue.empty() || m_moreMsgToGet) 
    { 
        std::string qname = "";
        if(!m_msgQueue.empty())
        {
            std::string subdomain = addDotEvery62Chars(m_msgQueue.front());
            qname += subdomain;
            qname+=".";
            m_msgQueue.pop();
        }
        else
        {
            qname = "admin";
            qname += generateRandomString(8);
            qname +=".";
        }
        
        qname+=m_domainToResolve;
        // TODO soit creat le qname avec les . ou faire que la function le face en solo
        query.setQName(qname);
        query.setQType(16);
        query.setQClass(1);

        nbytes=query.code(buffer);
        
        struct sockaddr_in serv_addr;
        fd_set read_fds;
        FD_ZERO(&read_fds);

#ifdef __linux__

        int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
        serv_addr.sin_port = htons(53);
        serv_addr.sin_family = AF_INET;
        inet_aton(m_dnsServerAdd.c_str(), &(serv_addr.sin_addr));

#elif _WIN32

        WSAData data;
        WSAStartup(MAKEWORD(2, 2), &data);

        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
        serv_addr.sin_port = htons(53);
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr( m_dnsServerAdd.c_str() );

#endif

        // test DnsQuery_A -> https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/netds/dns/dnsquery/DNSQuery.Cpp
        if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
        {
            std::cout << "Error occurred during connection" << std::endl;
            // return;
        }

        int t_len = sizeof(serv_addr);
        int req = sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &serv_addr, t_len);
        if(req < 1) 
        {
            std::cout << "Error occurred during sending" << std::endl;
            return;
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
                return;
            } 
            else 
            {	
                std::cout << "Error: select didn't work properly" << std::endl;
                return;
            }
        }

        #ifdef __linux__

        int received = recvfrom(sockfd, &buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);

        #elif _WIN32

        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);

        #endif

        Response response;
        response.decode(buffer, received);

        std::string rdata = response.getRdata();

        handleResponse(rdata);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}
