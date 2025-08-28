
#pragma once

#include <iostream>
#include <thread>
#include <memory>
#include <mutex>
#include <vector>
#include <queue>
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

#include "query.hpp"
#include "response.hpp"
#include "dnsPacker.hpp"


namespace dns 
{

class Dns
{

public:
    Dns(const std::string& domain);
    ~Dns();

    void setMsg(const std::string& msg);
    std::string getMsg();

    bool isMoreMsgToGet()
    {
        return m_moreMsgToGet;
    }


protected:
    void handleResponse(const std::string& rdata);
    void addReceivedQName(const std::string& qname);
    
    std::string m_domainToResolve;
    int m_maxMessageSize;

    std::queue<std::string> m_msgQueue;

    bool m_moreMsgToGet;
    std::unordered_map<std::string, Packet> m_msgReceived;
    std::vector<std::string> m_qnameReceived;

private:
    std::mutex m_mutex;

};


}



