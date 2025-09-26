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
void Dns::setMsg(const std::string& msg, const std::string& clientId)
{
    dns::debug::log("Dns::setMsg",
        "Preparing message of " + std::to_string(msg.size()) + " bytes" );

    const std::lock_guard<std::mutex> lock(m_mutex);

    m_msgToSend[clientId] = msg;
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
    if(it == m_msgToSend.end() || it->second.empty())
        return;

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
                            std::to_string(static_cast<unsigned long long>(it->second.size())) +
                            " byte message for client '" + clientId + "'");
        it->second.clear();
        return;
    }

    dns::debug::log("Dns::splitPacket",
                    "Preparing message of " + std::to_string(static_cast<unsigned long long>(it->second.size())) +
                        " bytes for domain '" + m_domainToResolve + "'");

    std::string sessionId = generateRandomString(2);

    dns::debug::log("Dns::splitPacket",
                    "Generated session identifier '" + sessionId + "'");

    json packetJson;
    packetJson["m"] = it->second;
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
            it->second.clear();
            return;
        }

        size_t totalLen = it->second.length();
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
            std::string tmp = it->second.substr(startPos, chunkSize);
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
                "' raw=" + std::to_string(static_cast<unsigned long long>(it->second.size())) + " bytes encoded=" +
                std::to_string(msgHex.size()) +
                " hex chars; queue size=" +
                std::to_string(static_cast<unsigned long long>(
                    m_msgQueue[clientId].size())));
    }

    it->second.clear();
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
void Dns::handleDataReceived(const std::string& rdata, const std::string& clientId)
{
    std::string msg = rdata;

    // no data was transmited we use the word
    if(startsWith(rdata, m_secretKeyClientAskData) || startsWith(rdata, m_secretKeyClientKeepAlive))
    {
        dns::debug::log("Dns::handleResponse",
                        "Ignoring control record '" + rdata + "'");
        return;
    }

    dns::debug::log("Dns::handleResponse",
                    "Processing RDATA of length " +
                        std::to_string(rdata.size()));

    // Remove all the dots - only hex data is transmited, no .
    auto noDot = std::remove(msg.begin(), msg.end(), '.');
    msg.erase(noDot, msg.end());

    // decode hex
    std::string msgReceived = hexToString(msg);

    // check validity of json
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
    }
    catch (...)
    {
        dns::debug::log("Dns::handleResponse",
                        "Failed to parse JSON fragment: unknown error");
        return;
    }

    std::string session = packetJson["s"];

    int k = packetJson["k"].get<int>();
    int n = packetJson["n"].get<int>();

    const std::string payload = packetJson["m"].get<std::string>();

    size_t accumulatedSize = 0;
    bool packetFull = false;
    bool morePending = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto& packet = m_msgReceived[clientId][session];
        if(packet.id.empty())
            packet.id = session;
        if(packet.clientId.empty() && !clientId.empty())
            packet.clientId = clientId;
        packet.data.append(payload);
        packet.isFull = (k == n-1);

        accumulatedSize = packet.data.size();
        packetFull = packet.isFull;

        m_moreMsgToGet = false;
        for(const auto& p : m_msgReceived[clientId])
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
        "Received fragment " + std::to_string(k + 1) + "/" +
            std::to_string(n) + " for session '" + session + "' payload=" +
            std::to_string(payload.size()) +
            " bytes; accumulated=" +
            std::to_string(static_cast<unsigned long long>(accumulatedSize)) +
            " bytes; isFull=" + (packetFull ? "true" : "false"));

    dns::debug::log("Dns::handleResponse",
                    std::string("More fragments pending: ") +
                        (morePending ? "yes" : "no"));
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
        dns::debug::log("Dns::getMsg",
            "Assembled complete message of " +
            std::to_string(static_cast<unsigned long long>(result.size())) +
            " bytes; remaining sessions=" +
            std::to_string(static_cast<unsigned long long>(m_msgReceived[foundClientId].size())));
    }

    return {foundClientId, result};
}
