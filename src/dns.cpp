#include <iostream>
#include <cstring>
#include <string>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <string_view>

#include "nlohmann/json.hpp"
#include "dns.hpp"
#include "debugLog.hpp"


using namespace std;
using namespace dns;

using json = nlohmann::json;

namespace
{
bool decodePacketJson(const std::string& encoded, json& packetJson)
{
    std::string compact = encoded;
    compact.erase(std::remove(compact.begin(), compact.end(), '.'), compact.end());

    std::string decoded;
    if (!tryHexToString(compact, decoded))
        return false;

    try
    {
        packetJson = json::parse(decoded);
    }
    catch (...)
    {
        return false;
    }
    return packetJson.is_object();
}

bool readFragmentIdentity(const json& packetJson, FragmentIdentity& identity)
{
    if (!packetJson.contains("s") || !packetJson["s"].is_string() ||
        !packetJson.contains("k") || !packetJson["k"].is_number_integer() ||
        !packetJson.contains("n") || !packetJson["n"].is_number_integer())
        return false;

    identity.session = packetJson["s"].get<std::string>();
    identity.index = packetJson["k"].get<int>();
    identity.count = packetJson["n"].get<int>();
    return !identity.session.empty();
}
}


Dns::Dns(const std::string& domain, const std::string& id)
    : m_domainToResolve(id + domain)
    , m_maxMessageSize(0)
    , m_moreMsgToGet(false)
{
    m_maxMessageSize = getMaxMsgLen(m_domainToResolve);

    dns::debug::log("Dns",
                    "Initialized for domain '" + m_domainToResolve +
                        "' with max payload size " +
                        std::to_string(m_maxMessageSize) + " bytes");
}

Dns::~Dns()
{
}

/**
 * @brief Store a message to be sent to a specific client.
 *
 * This function:
 *   - Locks the internal mutex (m_mutex) to ensure thread-safe access
 *     to the shared map of outgoing messages (m_msgToSend).
 *   - Associates the given message with the specified clientId
 *     in m_msgToSend (overwriting any previous pending message
 *     for that client).
 *
 * @param msg       The complete message to be queued for the client.
 * @param clientId  The identifier of the client who should receive the message.
 */
#undef min
bool Dns::setMsg(const std::string& msg, const std::string& clientId)
{
    dns::debug::log("Dns::setMsg",
        "Preparing message of " + std::to_string(msg.size()) + " bytes" );

    const std::lock_guard<std::mutex> lock(m_mutex);

    if (msg.empty() || msg.size() > MaxAssembledMessage || clientId.empty())
        return false;

    auto& pending = m_msgToSend[clientId];
    if (pending.size() >= MaxPendingMessagesPerClient)
        return false;

    pending.push(msg);
    return true;
}

/**
 * @brief Split and enqueue an outgoing message for a client into DNS-sized packets.
 *
 * This function takes the message prepared for a given client (m_msgToSend[clientId])
 * and breaks it into one or more fragments suitable for transmission via DNS responses.
 * 
 * Steps:
 *   1. If there is no message for the client, return immediately.
 *   2. Determine the maximum allowed payload size (`maxMessageSize`) based on the
 *      DNS query type (A, AAAA, MX, CNAME, NS, PTR, TXT, ...). Some types have no
 *      payload capacity (set to 0), while others use `m_maxMessageSize`.
 *   3. Log the message size and generate a random session identifier to track
 *      all fragments belonging to this message.
 *   4. Serialize the message, session ID, and metadata into JSON (`packetJson`).
 *   5. If the serialized message exceeds the maximum payload size:
 *        - Compute the maximum fragment size (accounting for JSON overhead).
 *        - Split the message into chunks of that size.
 *        - For each chunk:
 *            * Insert metadata (`n` = total number of fragments, `k` = fragment index).
 *            * Convert the JSON fragment to hex.
 *            * Push the encoded fragment into the per-client queue (m_msgQueue[clientId]).
 *   6. If the message fits within one payload:
 *        - Encode the JSON as hex.
 *        - Push it into the client’s queue as a single fragment.
 *   7. Finally, clear m_msgToSend[clientId] since the message has been enqueued
 *      for transmission.
 *
 * @param qType     The DNS query type (A, AAAA, MX, TXT, etc.), used to determine
 *                  the maximum payload size per packet.
 * @param clientId  The identifier of the client whose message is being fragmented
 *                  and queued.
 *
 * @note Each message is tagged with a session ID so fragments can be reassembled
 *       on the receiving side. Messages are hex-encoded to fit safely into DNS
 *       records. The function modifies m_msgQueue and clears the pending message
 *       from m_msgToSend for the given client.
 */

void Dns::splitPacket(int qType, const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_msgToSend.find(clientId);
    if(it == m_msgToSend.end() || it->second.empty() || !m_msgQueue[clientId].empty())
        return;

    const std::string message = it->second.front();

    int maxMessageSize;

    switch (qType)
    {
        case 1: // A
        {
            maxMessageSize = 0;
            break;
        }
        case 28: // AAAA
        {
            maxMessageSize = 0;
            break;
        }
        case 15: // MX
            maxMessageSize = m_maxMessageSize;
            break;
        case 5:  // CNAME
        case 2:  // NS
        case 12: // PTR
            maxMessageSize = m_maxMessageSize;
            break;
        case 16: // TXT
        default:
            maxMessageSize = m_maxMessageSize;
            break;
    }

    if(maxMessageSize <= 0)
    {
        dns::debug::log("Dns::splitPacket",
                        "Query type " + std::to_string(qType) +
                            " does not support payload transmission; dropping " +
                            std::to_string(static_cast<unsigned long long>(message.size())) +
                            " byte message for client '" + clientId + "'");
        it->second.pop();
        return;
    }

    dns::debug::log("Dns::splitPacket",
                    "Preparing message of " + std::to_string(static_cast<unsigned long long>(message.size())) +
                        " bytes for domain '" + m_domainToResolve + "'");

    std::string sessionId = generateRandomLowcaseString(8);

    dns::debug::log("Dns::splitPacket",
                    "Generated session identifier '" + sessionId + "'");

    json packetJson;
    packetJson["m"] = message;
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
        if(maxLength <= 0)
        {
            dns::debug::log("Dns::splitPacket",
                            "Message metadata exceeds maximum payload size (metadata=" +
                                std::to_string(static_cast<unsigned long long>(packet.size())) +
                                " bytes, capacity=" +
                                std::to_string(maxMessageSize) +
                                "); dropping message for client '" + clientId + "'");
            it->second.pop();
            return;
        }

        size_t totalLen = message.length();
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
            std::string tmp = message.substr(startPos, chunkSize);
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
            m_msgQueue[clientId].push(msgHex);

            dns::debug::log(
                "Dns::splitPacket",
                "Fragment " + std::to_string(i + 1) + "/" +
                    std::to_string(nbMaxMessage) + " for session '" +
                    sessionId + "' raw=" + std::to_string(chunkData.size()) +
                    " bytes encoded=" + std::to_string(msgHex.size()) +
                    " hex chars; queue size=" +
                    std::to_string(static_cast<unsigned long long>(
                        m_msgQueue[clientId].size())));
        }
    }
    else
    {
        std::string msgHex = stringToHex(packet);
        m_msgQueue[clientId].push(msgHex);

        dns::debug::log(
            "Dns::splitPacket",
            "Message fits in a single fragment for session '" + sessionId +
                "' raw=" + std::to_string(static_cast<unsigned long long>(message.size())) + " bytes encoded=" +
            std::to_string(msgHex.size()) +
                " hex chars; queue size=" +
                std::to_string(static_cast<unsigned long long>(
                    m_msgQueue[clientId].size())));
    }

    it->second.pop();
    if (it->second.empty())
        m_msgToSend.erase(it);
}

/**
 * @brief Process an incoming DNS RDATA string from a client and reconstruct message fragments.
 *
 * This function decodes and validates a DNS RDATA payload sent by a client and
 * appends it to the reassembly buffer for that client’s session.
 *
 * Steps:
 *   1. If the RDATA matches a control record (client ask-data / keep-alive),
 *      ignore it and return.
 *   2. Remove all '.' characters (the payload is hex-encoded and transmitted
 *      across DNS labels).
 *   3. Decode the remaining hex string back into raw data.
 *   4. Validate that the data contains a terminating '}' to ensure JSON completeness.
 *      If not, discard it.
 *   5. Parse the JSON safely with exception handling. On parse failure, discard
 *      the fragment.
 *   6. Extract session identifier (`s`), fragment index (`k`), total fragment
 *      count (`n`), and the payload (`m`) from the JSON.
 *   7. Insert or update the corresponding `Packet` entry in
 *      `m_msgReceived[clientId][session]`:
 *        - initialize session/client identifiers if needed,
 *        - append the payload to the accumulated message,
 *        - mark `isFull` true if this was the last fragment (k == n-1).
 *   8. Log fragment progress, including accumulated size and completeness.
 *   9. Recalculate `m_moreMsgToGet`: set to true if at least one fragment for
 *      this client is still incomplete.
 *
 * @param rdata     The raw RDATA string (hex-encoded fragments with optional dots).
 * @param clientId  The identifier of the client that sent the data.
 *
 * @note This function updates `m_msgReceived` (per-client session map) and sets
 *       `m_moreMsgToGet` accordingly. Fragments are expected to arrive in order
 *       but will still be accumulated until the final fragment marks completion.
 */
std::optional<FragmentIdentity> Dns::handleDataReceived(const std::string& rdata,
                                                        const std::string& clientId)
{
    if (rdata == m_secretKeyServerNoData)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_moreMsgToGet = false;
        return std::nullopt;
    }

    if (rdata == m_secretKeyClientAskData ||
        rdata == m_secretKeyClientKeepAlive ||
        rdata == m_secretKeyServerKeepAlive ||
        rdata == m_secretKeyAck)
    {
        dns::debug::log("Dns::handleResponse",
                        "Ignoring control record '" + rdata + "'");
        return std::nullopt;
    }

    if (clientId.empty() || rdata.size() > MaxFragmentPayload * 4)
        return std::nullopt;

    dns::debug::log("Dns::handleResponse",
                    "Processing RDATA of length " +
                        std::to_string(rdata.size()));

    json packetJson;
    FragmentIdentity identity;
    if (!decodePacketJson(rdata, packetJson) ||
        !readFragmentIdentity(packetJson, identity) ||
        !packetJson.contains("m") || !packetJson["m"].is_string())
        return std::nullopt;

    if (identity.session.size() > 32 ||
        !std::all_of(identity.session.begin(), identity.session.end(), [](unsigned char c) {
            return std::isalnum(c) != 0;
        }) ||
        identity.count <= 0 || identity.count > MaxFragmentsPerMessage ||
        identity.index < 0 || identity.index >= identity.count)
        return std::nullopt;

    const std::string payload = packetJson["m"].get<std::string>();
    if (payload.size() > MaxFragmentPayload)
        return std::nullopt;

    cleanupExpiredState();

    size_t accumulatedSize = 0;
    bool packetFull = false;
    bool morePending = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto clientIt = m_msgReceived.find(clientId);
        if (clientIt == m_msgReceived.end())
        {
            if (m_msgReceived.size() >= MaxClients)
                return std::nullopt;
            clientIt = m_msgReceived.emplace(clientId, decltype(m_msgReceived)::mapped_type{}).first;
        }

        auto& sessions = clientIt->second;
        auto sessionIt = sessions.find(identity.session);
        if (sessionIt == sessions.end())
        {
            if (sessions.size() >= MaxSessionsPerClient)
                return std::nullopt;

            size_t totalSessions = 0;
            for (const auto& client : m_msgReceived)
                totalSessions += client.second.size();
            if (totalSessions >= MaxTotalSessions)
                return std::nullopt;

            sessionIt = sessions.emplace(identity.session, Packet{}).first;
        }

        auto& packet = sessionIt->second;
        if(packet.id.empty())
            packet.id = identity.session;
        if(packet.clientId.empty() && !clientId.empty())
            packet.clientId = clientId;

        if (packet.expectedCount < 0)
        {
            packet.expectedCount = identity.count;
        }
        else if (packet.expectedCount != identity.count)
        {
            dns::debug::log(
                "Dns::handleResponse",
                "Fragment count mismatch for session '" + identity.session +
                    "' (expected " + std::to_string(packet.expectedCount) +
                    ", got " + std::to_string(identity.count) + ")");
            return std::nullopt;
        }

        auto existing = packet.fragments.find(identity.index);
        if (existing != packet.fragments.end() && existing->second != payload)
            return std::nullopt;

        packet.fragments[identity.index] = payload;
        packet.updatedAt = std::chrono::steady_clock::now();

        accumulatedSize = 0;
        for (const auto& fragment : packet.fragments)
        {
            accumulatedSize += fragment.second.size();
            if (accumulatedSize > MaxAssembledMessage)
            {
                sessions.erase(sessionIt);
                return std::nullopt;
            }
        }

        bool allPresent =
            packet.expectedCount > 0 &&
            packet.fragments.size() == static_cast<size_t>(packet.expectedCount);

        if (allPresent)
        {
            int expectedIndex = 0;
            for (const auto& entry : packet.fragments)
            {
                if (entry.first != expectedIndex)
                {
                    allPresent = false;
                    break;
                }
                ++expectedIndex;
            }
        }

        if (allPresent)
        {
            packet.data.clear();
            packet.data.reserve(accumulatedSize);
            for (const auto& entry : packet.fragments)
            {
                packet.data.append(entry.second);
            }
        }

        packet.isFull = allPresent;
        packetFull = packet.isFull;

        m_moreMsgToGet = false;
        for(const auto& p : sessions)
        {
            if(!p.second.isFull)
            {
                m_moreMsgToGet = true;
                break;
            }
        }

        morePending = m_moreMsgToGet;
    }

    dns::debug::log(
        "Dns::handleResponse",
        "Received fragment " + std::to_string(identity.index + 1) + "/" +
            std::to_string(identity.count) + " for session '" + identity.session + "' payload=" +
            std::to_string(payload.size()) +
            " bytes; accumulated=" +
            std::to_string(static_cast<unsigned long long>(accumulatedSize)) +
            " bytes; isFull=" + (packetFull ? "true" : "false"));

    dns::debug::log("Dns::handleResponse",
                    std::string("More fragments pending: ") +
                        (morePending ? "yes" : "no"));

    return identity;
}


std::optional<FragmentIdentity> Dns::queuedFragmentIdentity(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto queueIt = m_msgQueue.find(clientId);
    if (queueIt == m_msgQueue.end() || queueIt->second.empty())
        return std::nullopt;

    json packetJson;
    FragmentIdentity identity;
    if (!decodePacketJson(queueIt->second.front(), packetJson) ||
        !readFragmentIdentity(packetJson, identity))
        return std::nullopt;
    return identity;
}


std::string Dns::peekQueuedFragment(const std::string& clientId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto queueIt = m_msgQueue.find(clientId);
    if (queueIt == m_msgQueue.end() || queueIt->second.empty())
        return {};
    return queueIt->second.front();
}


bool Dns::acknowledgeQueuedFragment(const std::string& clientId,
                                    const std::string& session,
                                    int index)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto queueIt = m_msgQueue.find(clientId);
    if (queueIt == m_msgQueue.end() || queueIt->second.empty())
        return false;

    json packetJson;
    FragmentIdentity identity;
    if (!decodePacketJson(queueIt->second.front(), packetJson) ||
        !readFragmentIdentity(packetJson, identity) ||
        identity.session != session || identity.index != index)
        return false;

    queueIt->second.pop();
    if (queueIt->second.empty())
        m_msgQueue.erase(queueIt);
    return true;
}


void Dns::cleanupExpiredState()
{
    const auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(5);
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto clientIt = m_msgReceived.begin(); clientIt != m_msgReceived.end(); )
    {
        auto& sessions = clientIt->second;
        for (auto sessionIt = sessions.begin(); sessionIt != sessions.end(); )
        {
            if (sessionIt->second.updatedAt < cutoff)
                sessionIt = sessions.erase(sessionIt);
            else
                ++sessionIt;
        }

        if (sessions.empty())
            clientIt = m_msgReceived.erase(clientIt);
        else
            ++clientIt;
    }
}

/**
 * @brief Retrieve the first complete message from any client.
 *
 * This function scans through all clients in m_msgReceived and their
 * pending sessions. If it finds a session marked as complete
 * (Packet::isFull == true), it:
 *   - extracts the assembled message (Packet::data),
 *   - remembers which clientId it belongs to,
 *   - erases the completed session from the pending map,
 *   - sets m_moreMsgToGet = true,
 *   - logs the operation,
 *   - and immediately returns the pair {clientId, message}.
 *
 * If no complete session is found, it returns {"", ""}.
 *
 * @return std::pair<std::string, std::string>
 *         The first {clientId, message} found, or {"", ""} if none complete.
 */
std::pair<std::string, std::string> Dns::getMsg()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string result;
    std::string foundClientId;

    for (auto& clientPair : m_msgReceived) // iterate all clientIds
    {
        auto& clientId   = clientPair.first;
        auto& sessionMap = clientPair.second;

        for (auto it = sessionMap.begin(); it != sessionMap.end(); )
        {
            if (it->second.isFull)
            {
                std::string sessionId = it->first;
                result = it->second.data;
                foundClientId = clientId;

                it = sessionMap.erase(it);  // erase this session

                dns::debug::log("Dns::getMsg",
                    "Completed session '" + sessionId +
                    "' removed from pending map (client=" + clientId + ")");
                break; // stop scanning sessions for this client
            }
            else
            {
                ++it;
            }
        }

        if (!result.empty()) break; // stop after the first found
    }

    if (!result.empty())
    {
        const auto foundClient = m_msgReceived.find(foundClientId);
        const size_t remainingSessions =
            foundClient == m_msgReceived.end() ? 0 : foundClient->second.size();
        dns::debug::log("Dns::getMsg",
            "Assembled complete message of " +
            std::to_string(static_cast<unsigned long long>(result.size())) +
            " bytes; remaining sessions=" +
            std::to_string(static_cast<unsigned long long>(remainingSessions)));
        if (foundClient != m_msgReceived.end() && foundClient->second.empty())
            m_msgReceived.erase(foundClient);
    }

    return {foundClientId, result};
}
