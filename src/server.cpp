#include <iostream>
#include <cstring>

#include <algorithm>
#include <cctype>
#include <string_view>

#include <errno.h>

#include "server.hpp"


#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")

#endif

using namespace std;
using namespace dns;


Server::Server(int port, const std::string& domainToResolve) 
: Dns(domainToResolve)
, m_port(port)
{ 

}


Server::~Server() 
{ 
    m_isStoped=true;
    this->m_dnsServ->join();
}


void Server::stop()
{
    m_isStoped=true;
}


void Server::launch()
{
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
        m_qnameReceived.push_back(qname);

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
    
    if (domainName.empty()) 
    {
        // cout << "[-] Domain not in scope !" << endl;

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