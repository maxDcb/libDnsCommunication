#include <iostream>
#include <cstring>
#include <string>

#include <algorithm>
#include <cctype>
#include <string_view>

#include "nlohmann/json.hpp"
#include "dns.hpp"
#include "debugLog.hpp"


using namespace std;
using namespace dns;

using json = nlohmann::json;


Dns::Dns(const std::string& domain)
: m_domainToResolve(domain)
{
    m_maxMessageSize = getMaxMsgLen(domain);
    m_moreMsgToGet = false;

    dns::debug::log("Dns",
                    "Initialized for domain '" + m_domainToResolve +
                        "' with max payload size " +
                        std::to_string(m_maxMessageSize) + " bytes");
}


Dns::~Dns()
{
}

#undef min
void Dns::setMsg(const std::string& msg)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    dns::debug::log("Dns::setMsg",
                    "Preparing message of " + std::to_string(msg.size()) +
                        " bytes for domain '" + m_domainToResolve + "'");

    std::string sessionId;
    do
    {
        sessionId = generateRandomString(5);
    } while (m_msgReceived.find(sessionId) != m_msgReceived.end());

    dns::debug::log("Dns::setMsg",
                    "Generated session identifier '" + sessionId + "'");

    json packetJson;
    packetJson["m"] = msg;
    packetJson["s"] = sessionId;
    packetJson["n"] = 1;
    packetJson["k"] = 0;
    std::string packet = packetJson.dump();

    if(packet.size() > m_maxMessageSize)
    {
        std::vector<json> messages;
        packetJson["m"] = "";
        packetJson["n"] = 0;
        packetJson["k"] = 0;
        packet = packetJson.dump();

        int maxLength = m_maxMessageSize - static_cast<int>(packet.size());
        size_t totalLen = msg.length();
        size_t startPos = 0;

        dns::debug::log("Dns::setMsg",
                        "Message exceeds max payload size (" +
                            std::to_string(packet.size()) + " > " +
                            std::to_string(m_maxMessageSize) +
                            "), fragmenting with chunk capacity " +
                            std::to_string(maxLength) + " bytes");
        while (startPos < totalLen)
        {
            size_t chunkSize = std::min<size_t>(maxLength, totalLen - startPos);
            std::string tmp = msg.substr(startPos, chunkSize);
            packetJson["m"] = tmp;
            messages.push_back(packetJson);
            startPos += chunkSize;
        }

        size_t nbMaxMessage = messages.size();
        dns::debug::log("Dns::setMsg",
                        "Enqueued " + std::to_string(nbMaxMessage) +
                            " fragment(s) for session '" + sessionId + "'");
        for(size_t i = 0; i < nbMaxMessage; ++i)
        {
            const std::string chunkData = messages[i]["m"].get<std::string>();
            messages[i]["n"] = nbMaxMessage;
            messages[i]["k"] = i;
            std::string msgHex = stringToHex(messages[i].dump());
            m_msgQueue.push(msgHex);

            dns::debug::log(
                "Dns::setMsg",
                "Fragment " + std::to_string(i + 1) + "/" +
                    std::to_string(nbMaxMessage) + " for session '" +
                    sessionId + "' raw=" + std::to_string(chunkData.size()) +
                    " bytes encoded=" + std::to_string(msgHex.size()) +
                    " hex chars; queue size=" +
                    std::to_string(static_cast<unsigned long long>(
                        m_msgQueue.size())));
        }
    }
    else
    {
        std::string msgHex = stringToHex(packet);
        m_msgQueue.push(msgHex);

        dns::debug::log(
            "Dns::setMsg",
            "Message fits in a single fragment for session '" + sessionId +
                "' raw=" + std::to_string(msg.size()) + " bytes encoded=" +
                std::to_string(msgHex.size()) +
                " hex chars; queue size=" +
                std::to_string(static_cast<unsigned long long>(
                    m_msgQueue.size())));
    }
}

void Dns::addReceivedQName(const std::string& qname)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_qnameReceived.push_back(qname);

    dns::debug::log(
        "Dns::addReceivedQName",
        "Queued received QNAME '" + qname + "'; pending count=" +
            std::to_string(
                static_cast<unsigned long long>(m_qnameReceived.size())));
}


void Dns::handleResponse(const std::string& rdata)
{
    // std::string msg = rdata.substr(0, rdata.length() - m_domainToResolve.size() - 1); // to account for the final .
    std::string msg = rdata;

    // std::cout << "handleResponse:: rdata " << rdata << std::endl;

    if(startsWith(rdata, "admin"))
    {
        dns::debug::log("Dns::handleResponse",
                        "Ignoring control record '" + rdata + "'");
        return;
    }

    dns::debug::log("Dns::handleResponse",
                    "Processing RDATA of length " +
                        std::to_string(rdata.size()));

    // Remove all the dots
    auto noDot = std::remove(msg.begin(), msg.end(), '.');
    msg.erase(noDot, msg.end());

    // decode hex
    std::string msgReceived = hexToString(msg);

    // std::cout << "handleResponse:: msgReceived " << msgReceived << std::endl;

    // std::cout << "handleResponse:: FUCKKKK " << msgReceived << std::endl;

    size_t lastBracePos = msgReceived.find_last_of('}');
    if (lastBracePos == std::string::npos)
    {
        dns::debug::log("Dns::handleResponse",
                        "Discarded response missing JSON terminator; raw='" +
                            msgReceived + "'");
        return;
    }

    json packetJson;
    try
    {
        packetJson = json::parse(msgReceived.substr(0, lastBracePos+1));
    }
    catch (const std::exception& e)
    {
        dns::debug::log(
            "Dns::handleResponse",
            std::string("Failed to parse JSON fragment: ") + e.what());
        return;
        // Catching all exceptions derived from std::exception
    }
    catch (...)
    {
        dns::debug::log("Dns::handleResponse",
                        "Failed to parse JSON fragment: unknown error");
        return;
        // Catching all other exceptions not derived from std::exception
    }

    // std::cout << "handleResponse:: packetJson " << packetJson << std::endl;

    std::string session = packetJson["s"];

    int k = packetJson["k"].get<int>();
    int n = packetJson["n"].get<int>();

    const std::string payload = packetJson["m"].get<std::string>();

    auto& packet = m_msgReceived[session];
    if(packet.id.empty())
        packet.id = session;
    packet.data.append(payload);
    packet.isFull = (k == n-1);

    dns::debug::log(
        "Dns::handleResponse",
        "Received fragment " + std::to_string(k + 1) + "/" +
            std::to_string(n) + " for session '" + session + "' payload=" +
            std::to_string(payload.size()) +
            " bytes; accumulated=" +
            std::to_string(static_cast<unsigned long long>(packet.data.size())) +
            " bytes; isFull=" + (packet.isFull ? "true" : "false"));

    m_moreMsgToGet = false;
    for(const auto& p : m_msgReceived)
    {
        if(!p.second.isFull)
        {
            m_moreMsgToGet = true;
            break;
        }
    }

    dns::debug::log("Dns::handleResponse",
                    std::string("More fragments pending: ") +
                        (m_moreMsgToGet ? "yes" : "no"));
}


// return the first message that is available, or an empty string if no message is avalable
std::string Dns::getMsg()
{
    // only for server, for client handleResponse is executed on each process and qnameTmp is empty
    std::unique_lock<std::mutex> lock(m_mutex);

    std::vector<std::string> qnameTmp = m_qnameReceived;
    m_qnameReceived.clear();

    lock.unlock();

    dns::debug::log(
        "Dns::getMsg",
        "Processing " +
            std::to_string(static_cast<unsigned long long>(qnameTmp.size())) +
            " queued QNAME(s)");

    for(int i=0; i<qnameTmp.size(); i++)
        handleResponse(qnameTmp[i]);

    std::string result;
    for (auto it = m_msgReceived.begin(); it != m_msgReceived.end();)
    {
        if (it->second.isFull)
        {
            std::string sessionId = it->first;
            result = it->second.data;
            it = m_msgReceived.erase(it);
            dns::debug::log(
                "Dns::getMsg",
                "Completed session '" + sessionId +
                    "' removed from pending map");
            break;
        }
        else
        {
            ++it;
        }
    }

    m_moreMsgToGet = false;
    for(const auto& p : m_msgReceived)
    {
        if(!p.second.isFull)
        {
            m_moreMsgToGet = true;
            break;
        }
    }

    if(!result.empty())
    {
        dns::debug::log(
            "Dns::getMsg",
            "Assembled complete message of " +
                std::to_string(static_cast<unsigned long long>(result.size())) +
                " bytes; remaining sessions=" +
                std::to_string(
                    static_cast<unsigned long long>(m_msgReceived.size())));
    }
    else
    {
        dns::debug::log(
            "Dns::getMsg",
            "No complete message available; pending sessions=" +
                std::to_string(
                    static_cast<unsigned long long>(m_msgReceived.size())) +
                ", expecting more fragments=" +
                (m_moreMsgToGet ? std::string("true") : std::string("false")));
    }

    return result;
}