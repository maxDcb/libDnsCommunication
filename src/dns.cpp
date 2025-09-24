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

namespace
{

size_t hexChunkSizeForType(int qType)
{
    switch (qType)
    {
        case 1:  // A
            return 8;   // 4 bytes, two hex chars per byte
        case 28: // AAAA
            return 32;  // 16 bytes
        default:
            return 0;   // no additional splitting required
    }
}

size_t findCompleteJsonLength(const std::string& buffer)
{
    size_t start = 0;
    while (start < buffer.size())
    {
        unsigned char c = static_cast<unsigned char>(buffer[start]);
        if (c == 0 || std::isspace(c))
            ++start;
        else
            break;
    }

    if (start >= buffer.size() || buffer[start] != '{')
        return std::string::npos;

    bool inString = false;
    bool escape = false;
    int depth = 0;

    for (size_t i = start; i < buffer.size(); ++i)
    {
        unsigned char c = static_cast<unsigned char>(buffer[i]);

        if (escape)
        {
            escape = false;
            continue;
        }

        if (inString)
        {
            if (c == '\\')
            {
                escape = true;
            }
            else if (c == '"')
            {
                inString = false;
            }
            continue;
        }

        if (c == '"')
        {
            inString = true;
            continue;
        }

        if (c == '{')
        {
            ++depth;
        }
        else if (c == '}')
        {
            if (depth == 0)
                return std::string::npos;

            --depth;
            if (depth == 0)
                return i + 1;
        }
    }

    return std::string::npos;
}

void trimJsonBufferPrefix(std::string& buffer)
{
    size_t pos = 0;
    while (pos < buffer.size())
    {
        unsigned char c = static_cast<unsigned char>(buffer[pos]);
        if (c == 0 || std::isspace(c))
            ++pos;
        else
            break;
    }

    if (pos > 0)
        buffer.erase(0, pos);
}

}


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
    dns::debug::log("Dns::setMsg",
        "Preparing message of " + std::to_string(msg.size()) + " bytes" );

    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        m_msg = msg;
        m_msgRaw = msg;

        std::queue<std::string> empty;
        std::swap(m_msgQueue, empty);
    }

    splitPacket(5);
}

void Dns::splitPacket(int qType)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if(m_msg.empty())
    {
        if(m_msgRaw.empty())
            return;
        m_msg = m_msgRaw;
    }

    std::queue<std::string> emptyQueue;
    std::swap(m_msgQueue, emptyQueue);

    int maxMessageSize = m_maxMessageSize;

    switch (qType)
    {
        case 15: // MX
        case 5:  // CNAME
        case 2:  // NS
        case 12: // PTR
        case 16: // TXT
        case 1:  // A
        case 28: // AAAA
        default:
            // For all record types we keep the conservative limit derived
            // from the authoritative domain to ensure the encoded name fits
            // within 255 bytes.
            maxMessageSize = m_maxMessageSize;
            break;
    }

    dns::debug::log("Dns::splitPacket",
                    "Preparing message of " + std::to_string(m_msg.size()) +
                        " bytes for domain '" + m_domainToResolve + "'");

    std::string sessionId;
    do
    {
        sessionId = generateRandomString(5);
    } while (m_msgReceived.find(sessionId) != m_msgReceived.end());

    dns::debug::log("Dns::splitPacket",
                    "Generated session identifier '" + sessionId + "'");

    json packetJson;
    packetJson["m"] = m_msg;
    packetJson["s"] = sessionId;
    packetJson["n"] = 1;
    packetJson["k"] = 0;
    std::string packet = packetJson.dump();

    if(packet.size() > maxMessageSize)
    {
        std::vector<json> messages;
        packetJson["m"] = "";
        packetJson["n"] = 0;
        packetJson["k"] = 0;
        packet = packetJson.dump();

        int maxLength = maxMessageSize - static_cast<int>(packet.size());
        if (maxLength < 1)
            maxLength = 1;

        size_t totalLen = m_msg.length();
        size_t startPos = 0;

        dns::debug::log("Dns::splitPacket",
                        "Message exceeds max payload size (" +
                            std::to_string(packet.size()) + " > " +
                            std::to_string(maxMessageSize) +
                            "), fragmenting with chunk capacity " +
                            std::to_string(maxLength) + " bytes");
        while (startPos < totalLen)
        {
            size_t chunkSize = std::min<size_t>(maxLength, totalLen - startPos);
            std::string tmp = m_msg.substr(startPos, chunkSize);
            packetJson["m"] = tmp;
            messages.push_back(packetJson);
            startPos += chunkSize;
        }

        size_t nbMaxMessage = messages.size();
        dns::debug::log("Dns::splitPacket",
                        "Enqueued " + std::to_string(nbMaxMessage) +
                            " fragment(s) for session '" + sessionId + "'");
        for(size_t i = 0; i < nbMaxMessage; ++i)
        {
            const std::string chunkData = messages[i]["m"].get<std::string>();
            messages[i]["n"] = nbMaxMessage;
            messages[i]["k"] = i;

            std::string msgHex = stringToHex(messages[i].dump());
            size_t chunkLimit = hexChunkSizeForType(qType);
            size_t pieces = std::max<size_t>(1, chunkLimit ?
                (msgHex.size() + chunkLimit - 1) / chunkLimit : 1);

            for (size_t offset = 0, piece = 0; offset < msgHex.size() || (msgHex.empty() && piece == 0); ++piece)
            {
                size_t remaining = offset < msgHex.size() ? msgHex.size() - offset : 0;
                size_t take = chunkLimit ? std::min(chunkLimit, remaining) : remaining;
                std::string chunk = (take > 0) ? msgHex.substr(offset, take) : std::string();
                if (chunkLimit)
                {
                    if (chunk.size() < chunkLimit)
                        chunk.append(chunkLimit - chunk.size(), '0');
                    offset += take;
                }
                else
                {
                    offset += take;
                }

                m_msgQueue.push(chunk);

                dns::debug::log(
                    "Dns::splitPacket",
                    "Fragment " + std::to_string(i + 1) + "/" +
                        std::to_string(nbMaxMessage) + " for session '" +
                        sessionId + "' raw=" +
                        std::to_string(chunkData.size()) +
                        " bytes encoded=" +
                        std::to_string(msgHex.size()) +
                        " hex chars chunk=" +
                        std::to_string(piece + 1) + "/" +
                        std::to_string(pieces) + " chunkSize=" +
                        std::to_string(chunk.size()) +
                        "; queue size=" +
                        std::to_string(static_cast<unsigned long long>(
                            m_msgQueue.size())));

                if (!chunkLimit || offset >= msgHex.size())
                    break;
            }
        }
    }
    else
    {
        std::string msgHex = stringToHex(packet);
        size_t chunkLimit = hexChunkSizeForType(qType);
        size_t pieces = std::max<size_t>(1, chunkLimit ?
            (msgHex.size() + chunkLimit - 1) / chunkLimit : 1);

        for (size_t offset = 0, piece = 0; offset < msgHex.size() || (msgHex.empty() && piece == 0); ++piece)
        {
            size_t remaining = offset < msgHex.size() ? msgHex.size() - offset : 0;
            size_t take = chunkLimit ? std::min(chunkLimit, remaining) : remaining;
            std::string chunk = (take > 0) ? msgHex.substr(offset, take) : std::string();
            if (chunkLimit)
            {
                if (chunk.size() < chunkLimit)
                    chunk.append(chunkLimit - chunk.size(), '0');
                offset += take;
            }
            else
            {
                offset += take;
            }

            m_msgQueue.push(chunk);

            dns::debug::log(
                "Dns::splitPacket",
                "Message fits in a single JSON fragment for session '" +
                    sessionId + "' raw=" +
                    std::to_string(m_msg.size()) +
                    " bytes encoded=" + std::to_string(msgHex.size()) +
                    " hex chars chunk=" +
                    std::to_string(piece + 1) + "/" +
                    std::to_string(pieces) + " chunkSize=" +
                    std::to_string(chunk.size()) + "; queue size=" +
                    std::to_string(static_cast<unsigned long long>(
                        m_msgQueue.size())));

            if (!chunkLimit || offset >= msgHex.size())
                break;
        }
    }

    m_msg.clear();
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
    std::string msg = rdata;

    if(startsWith(rdata, "admin"))
    {
        dns::debug::log("Dns::handleResponse",
                        "Ignoring control record '" + rdata + "'");
        return;
    }

    dns::debug::log("Dns::handleResponse",
                    "Processing RDATA of length " +
                        std::to_string(rdata.size()));

    auto noDot = std::remove(msg.begin(), msg.end(), '.');
    msg.erase(noDot, msg.end());

    if (msg.empty())
    {
        dns::debug::log("Dns::handleResponse",
                        "Discarded empty RDATA payload after dot removal");
        return;
    }

    if (msg.size() % 2 != 0)
    {
        dns::debug::log("Dns::handleResponse",
                        "Discarded response with odd hex length; raw='" + msg + "'");
        return;
    }

    std::string decoded = hexToString(msg);
    if (decoded.empty() && !msg.empty())
    {
        dns::debug::log("Dns::handleResponse",
                        "Failed to decode hex payload; raw='" + msg + "'");
        return;
    }

    m_partialResponseBuffer.append(decoded);
    dns::debug::log("Dns::handleResponse",
                    "Appended " + std::to_string(decoded.size()) +
                        " byte(s); buffered=" +
                        std::to_string(m_partialResponseBuffer.size()));

    bool processedAny = false;

    while (true)
    {
        trimJsonBufferPrefix(m_partialResponseBuffer);
        size_t jsonLen = findCompleteJsonLength(m_partialResponseBuffer);
        if (jsonLen == std::string::npos)
        {
            m_moreMsgToGet = !m_partialResponseBuffer.empty();
            if (m_moreMsgToGet)
            {
                dns::debug::log("Dns::handleResponse",
                                "Awaiting more data to complete JSON fragment; buffered=" +
                                    std::to_string(m_partialResponseBuffer.size()) +
                                    " byte(s)");
            }
            break;
        }

        std::string jsonPayload = m_partialResponseBuffer.substr(0, jsonLen);
        m_partialResponseBuffer.erase(0, jsonLen);
        processedAny = true;

        json packetJson;
        try
        {
            packetJson = json::parse(jsonPayload);
        }
        catch (const std::exception& e)
        {
            dns::debug::log(
                "Dns::handleResponse",
                std::string("Failed to parse JSON fragment: ") + e.what());
            m_partialResponseBuffer.clear();
            return;
        }
        catch (...)
        {
            dns::debug::log("Dns::handleResponse",
                            "Failed to parse JSON fragment: unknown error");
            m_partialResponseBuffer.clear();
            return;
        }

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
                std::to_string(n) + " for session '" + session +
                "' payload=" + std::to_string(payload.size()) +
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

        if (!m_partialResponseBuffer.empty())
            m_moreMsgToGet = true;

        dns::debug::log("Dns::handleResponse",
                        std::string("More fragments pending: ") +
                            (m_moreMsgToGet ? "yes" : "no"));
    }

    if (!processedAny && !m_moreMsgToGet)
        m_moreMsgToGet = false;
}


// return the first message that is available, or an empty string if no message is avalable
std::string Dns::getMsg()
{
    // only for server, for client handleResponse is executed on each process and qnameTmp is empty
    std::unique_lock<std::mutex> lock(m_mutex);

    std::vector<std::string> qnameTmp = m_qnameReceived;
    m_qnameReceived.clear();

    lock.unlock();

    if(qnameTmp.size()>0)
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
        if(m_msgReceived.size()>0)
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