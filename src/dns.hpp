
#pragma once

#include <iostream>
#include <thread>
#include <memory>
#include <mutex>
#include <optional>
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

struct FragmentIdentity
{
    std::string session;
    int index = -1;
    int count = 0;
};

class Dns
{

public:
    Dns(const std::string& domain, const std::string& id);
    ~Dns();

protected:
    bool setMsg(const std::string& msg, const std::string& clientId);
    std::pair<std::string, std::string> getMsg();

    std::optional<FragmentIdentity> handleDataReceived(const std::string& rdata, const std::string& clientId);
    void splitPacket(int qType, const std::string& clientId);
    std::optional<FragmentIdentity> queuedFragmentIdentity(const std::string& clientId);
    std::string peekQueuedFragment(const std::string& clientId);
    bool acknowledgeQueuedFragment(const std::string& clientId,
                                   const std::string& session,
                                   int index);
    void cleanupExpiredState();
    
    std::string m_domainToResolve;
    int m_maxMessageSize;

    std::unordered_map<std::string, std::queue<std::string>> m_msgToSend;
    std::unordered_map<std::string, std::queue<std::string>> m_msgQueue;

    bool m_moreMsgToGet;
    std::unordered_map<std::string, std::unordered_map<std::string, Packet>> m_msgReceived;

    const std::string m_secretKeyClientAskData = "ask";
    const std::string m_secretKeyClientKeepAlive = "hello";
    const std::string m_secretKeyServerNoData = "noData";
    const std::string m_secretKeyServerKeepAlive = "olleh";
    const std::string m_secretKeyAck = "ack";

    std::mutex m_mutex;    

    static constexpr std::size_t MaxPendingMessagesPerClient = 64;
    static constexpr std::size_t MaxClients = 1024;
    static constexpr std::size_t MaxSessionsPerClient = 64;
    static constexpr std::size_t MaxTotalSessions = 256;
    static constexpr int MaxFragmentsPerMessage = 4096;
    static constexpr std::size_t MaxFragmentPayload = 4096;
    static constexpr std::size_t MaxAssembledMessage = 1024 * 1024;

};


}



