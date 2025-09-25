
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
    Dns(const std::string& domain, const std::string& id);
    ~Dns();

protected:
    void setMsg(const std::string& msg, const std::string& clientId);
    std::pair<std::string, std::string> getMsg();

    void handleDataReceived(const std::string& rdata, const std::string& clientId);
    void splitPacket(int qType, const std::string& clientId, uint16_t udpPayloadHint = 0);
    
    std::string m_domainToResolve;
    int m_maxMessageSize;

    std::unordered_map<std::string, std::string> m_msgToSend;
    std::unordered_map<std::string, std::queue<std::string>> m_msgQueue;

    bool m_moreMsgToGet;
    std::unordered_map<std::string, std::unordered_map<std::string, Packet>> m_msgReceived;
    std::vector<std::string> m_qnameReceived;

    const std::string m_secretKeyClientAskData = "ask";
    const std::string m_secretKeyClientKeepAlive = "hello";
    const std::string m_secretKeyServerNoData = "noData";
    const std::string m_secretKeyServerKeepAlive = "olleh";
    const std::string m_secretKeyAck = "ack";

    std::mutex m_mutex;    

};


}



