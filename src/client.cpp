#include <iostream>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <string_view>
#include <errno.h>
#ifdef __linux__
#include <unistd.h>
#elif _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "client.hpp"
#include "debugLog.hpp"

using namespace std;
using namespace dns;


Client::Client(const std::string& dnsServerAdd, const std::string& domainToResolve, int port)
: Dns(domainToResolve, generateRandomLowcaseString(3)+".")
, m_dnsServerAdd(dnsServerAdd)
, m_port(port)
{
}

Client::~Client()
{
}

/**
 * @brief Send an application message to the DNS server using DNS queries as transport.
 *
 * This function implements the client-side transmission loop for sending
 * application data encoded inside DNS queries and processing the corresponding
 * server responses.
 *
 * Steps:
 *   1. Prepare a DNS query template (`Query`), setting base header fields.
 *   2. If a new payload (`msg`) is provided:
 *        - Store it with setMsg(),
 *        - Split it into DNS-sized fragments with splitPacket() and enqueue them
 *          into m_msgQueue["serv"].
 *      Otherwise, reuse any already queued fragments.
 *   3. Create a UDP socket, set up the server address (IPv4 only here), and
 *      perform a diagnostic connect() to check connectivity.
 *   4. Enter the transmission loop, continuing until the per-client fragment
 *      queue (m_msgQueue["serv"]) is empty:
 *        - Dequeue the next fragment, convert it into a DNS QNAME (splitting the
 *          hex into labels with addDotEvery62Chars), or send a keep-alive
 *          control query if no data is pending.
 *        - Construct the full QNAME (fragment/keep-alive + domain) and encode
 *          it into the DNS query.
 *        - Send the query via sendto().
 *        - Wait for a response using select() with a timeout, then call recvfrom()
 *          to read the DNS response.
 *        - Parse the DNS response into a Response object, extract the RDATA,
 *          and log a preview of the returned payload.
 *        - Hand off the RDATA for processing (handleDataReceived is typically
 *          invoked elsewhere after decode).
 *        - Apply an inter-query delay (100 ms by default) to avoid flooding
 *          the resolver; TODO: make this configurable.
 *   5. Once the queue is empty, log the total session duration, close the UDP
 *      socket, and clean up (platform-specific).
 *
 * @param msg  The application payload to send. If empty, the function will
 *             only transmit already queued fragments or issue keep-alive
 *             queries.
 *
 * @note
 * - Messages are hex-encoded and split into DNS-compatible chunks to fit inside
 *   CNAME queries (QTYPE = 5).
 * - Transmission is rate-limited with a fixed delay to avoid resolver
 *   throttling/blacklisting.
 * - On Windows, WSAStartup/WSACleanup are used for socket initialization and cleanup.
 * - Debug logging provides detailed visibility into queue size, fragmenting,
 *   timing, and socket operations.
 */
void Client::sendMessage(const std::string& msg)
{
    char buffer[BUFFER_SIZE];
    int nbytes = 0;

    Query query;
    query.setID(0);
    query.setQdCount(1);
    query.setAnCount(0);
    query.setNsCount(0);
    query.setArCount(0);

    dns::debug::log("Client::sendMessage", "Preparing transmission to DNS server " + m_dnsServerAdd + ":" + std::to_string(m_port));

    if(!msg.empty())
    {
        dns::debug::log(
            "Client::sendMessage",
            "Queueing new payload of " +
                std::to_string(static_cast<unsigned long long>(msg.size())) +
                " bytes");

        // split the msg to send into packet of the right size of the recorde we intend to send: those packet or in m_msgQueue
        setMsg(msg, "serv");
        splitPacket(5, "serv");
    }
    else
    {
        dns::debug::log("Client::sendMessage", "No new payload provided; sending queued fragments");
    }

    dns::debug::log("Client::sendMessage", "Outbound fragment queue contains " + std::to_string(static_cast<unsigned long long>(m_msgQueue["serv"].size())) + " item(s); awaiting more fragments=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

    struct sockaddr_in serv_addr;
    fd_set read_fds;
    FD_ZERO(&read_fds);

#ifdef __linux__
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    inet_aton(m_dnsServerAdd.c_str(), &(serv_addr.sin_addr));
#elif _WIN32
    WSAData data;
    WSAStartup(MAKEWORD(2, 2), &data);
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr( m_dnsServerAdd.c_str() );
#endif

    dns::debug::log("Client::sendMessage", "UDP socket created; attempting connection test via connect()");

    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    {
        dns::debug::log("Client::sendMessage", "connect() failed; continuing with sendto/recvfrom");
    }
    else
    {
        dns::debug::log("Client::sendMessage", "connect() succeeded for diagnostic connection check");
    }

    size_t iteration = 0;
    auto sessionStart = std::chrono::steady_clock::now();

    // util we sent all we need to send (m_msgQueue) 
    while(!m_msgQueue["serv"].empty())
    {
        ++iteration;
        auto iterationStart = std::chrono::steady_clock::now();
        dns::debug::log( "Client::sendMessage", "Iteration " + std::to_string(iteration) + ": fragments remaining before dequeue=" + std::to_string(static_cast<unsigned long long>(m_msgQueue.size())));

        // qname will transport the data to send if any
        std::string qname;
        if(!m_msgQueue["serv"].empty())
        {
            const std::string fragmentHex = m_msgQueue["serv"].front();
            std::string preview = fragmentHex.substr(0, 60);
            if(fragmentHex.size() > preview.size())
                preview += "...";

            std::string subdomain = addDotEvery62Chars(fragmentHex);
            qname += subdomain;
            qname += ".";

            dns::debug::log( "Client::sendMessage", "Dequeued fragment hex-length=" + std::to_string( static_cast<unsigned long long>(fragmentHex.size())) + " preview='" + preview + "'");
        }
        // if no data is available we use a word to signify we are a beacon - control data
        else
        {
            qname = m_secretKeyClientKeepAlive;
            qname += ".";
            qname += generateRandomString(8); // avoid caching
            qname += ".";

            dns::debug::log("Client::sendMessage", "No fragment ready; issuing keep-alive query '" + qname + "'");
        }

        // we add the domain to resolve to ensure we talk to the server
        qname += m_domainToResolve;
        query.setQName(qname);
        // TODO put random
        query.setQType(5);
        query.setQClass(1);

        nbytes = query.code(buffer);

        dns::debug::log( "Client::sendMessage", "Encoded query length=" + std::to_string(nbytes) + " bytes for QNAME '" + qname + "'");

        // send udp data
        int t_len = sizeof(serv_addr);
        int req = sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &serv_addr, t_len);
        if(req < 1)
        {
            dns::debug::log("Client::sendMessage", "sendto() failed with return value " + std::to_string(req));
            break;
        }

        auto afterSend = std::chrono::steady_clock::now();
        dns::debug::log( "Client::sendMessage", "Sent " + std::to_string(req) + " bytes to " + m_dnsServerAdd + ":" + std::to_string(m_port) + " (" + dns::debug::formatDuration(afterSend - iterationStart) + " since iteration start)");

        // wait for the replay
        FD_SET(sockfd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 10;
        int selection = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        auto afterSelect = std::chrono::steady_clock::now();

        if(selection < 1)
        {
            if (selection != -1)
            {
                FD_CLR(sockfd, &read_fds);
                dns::debug::log( "Client::sendMessage", "select() timeout after " + dns::debug::formatDuration(afterSelect - afterSend));
                break;
            }
            else
            {
                dns::debug::log("Client::sendMessage", "select() returned error after " + dns::debug::formatDuration(afterSelect - afterSend));
                break;
            }
        }

#ifdef __linux__
        int received = recvfrom(sockfd, &buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#elif _WIN32
        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#endif

        auto afterRecv = std::chrono::steady_clock::now();

        dns::debug::log( "Client::sendMessage", "recvfrom() returned " + std::to_string(received) + " bytes after " + dns::debug::formatDuration(afterRecv - afterSend));

        // all messages are part of the final payload that need to be put together
        // decode extract the data using parse_rdata and the record type received
        Response response;
        response.decode(buffer, received);

        std::string rdata = response.getRdata();

        if(rdata.contains(m_secretKeyAck))  
        {
            if(!m_msgQueue["serv"].empty())
            {
                dns::debug::log("Client::sendMessage", "Server acknowledged fragment, dequeuing");
                m_msgQueue["serv"].pop();  // now safe to remove$
            }
        }
        else
        {
            dns::debug::log("Client::sendMessage", "Server did not ACK, fragment remains queued");
        }

        std::string rdataPreview = rdata.substr(0, 60);
        if(rdata.size() > rdataPreview.size())
            rdataPreview += "...";
        dns::debug::log( "Client::sendMessage", "Received RDATA length=" + std::to_string(static_cast<unsigned long long>(rdata.size())) + " preview='" + rdataPreview + "'");

        auto afterHandle = std::chrono::steady_clock::now();
        dns::debug::log( "Client::sendMessage", "Response handling completed in " + dns::debug::formatDuration(afterHandle - afterRecv) + "; fragments remaining=" + std::to_string(static_cast<unsigned long long>(m_msgQueue["serv"].size())) +", awaiting more=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

        dns::debug::log("Client::sendMessage", "Applying inter-query delay of 100 ms to avoid flooding");
      
         // TODO make it configurable - Resolvers usually accept ~5–20 qps per client without rate-limiting. Above that, some will throttle or blacklist.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        dns::debug::log( "Client::sendMessage", "Iteration " + std::to_string(iteration) + " total time " + dns::debug::formatDuration(std::chrono::steady_clock::now() - iterationStart));
    }

    dns::debug::log( "Client::sendMessage", "Transmission loop completed after " + dns::debug::formatDuration(std::chrono::steady_clock::now() - sessionStart) + "; remaining fragments=" + std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) + ", awaiting more=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

#ifdef __linux__
    close(sockfd);
#elif _WIN32
    closesocket(sockfd);
    WSACleanup();
#endif

    dns::debug::log("Client::sendMessage", "Socket closed");
}

/**
 * @brief Request and reassemble a complete message from the DNS server.
 *
 * This function drives the client-side "receive" loop. It sends special DNS
 * queries that act as requests for server messages, then collects and
 * reassembles message fragments delivered via TXT records.
 *
 * Steps:
 *   1. Prepare a DNS query template (`Query`) with standard header fields.
 *   2. Create and configure a UDP socket to the target DNS server (Linux/Windows
 *      implementations differ slightly).
 *   3. Attempt a diagnostic connect() call; log whether it succeeds or fails.
 *   4. Enter a do/while loop that continues as long as more message fragments
 *      are expected (`m_moreMsgToGet`):
 *        - Increment iteration counter and log state.
 *        - Build the query name (QNAME) starting with a control keyword
 *          (`m_secretKeyClientAskData`) to signal a data request, followed by
 *          the configured domain (`m_domainToResolve`).
 *        - Encode the query as a TXT request and send it with sendto().
 *        - Wait for a response using select() with a 10-second timeout.
 *        - If data is received, decode the DNS response, extract the RDATA,
 *          and log a preview.
 *        - Pass the RDATA to handleDataReceived() for JSON decoding and
 *          fragment reassembly.
 *        - Sleep 100 ms between queries to avoid overloading the resolver.
 *   5. Once all fragments are received, call getMsg() to retrieve the complete
 *      reassembled message and the associated client ID.
 *   6. Log transmission statistics, close the socket (platform-specific), and
 *      return the final message.
 *
 * @return std::string
 *         The fully reassembled message received from the DNS server,
 *         or an empty string if no complete message was available.
 *
 * @note
 * - This method uses a beacon-style query (`m_secretKeyClientAskData`) to
 *   request pending data from the server.
 * - Responses are expected to be JSON-encoded, hex-transmitted fragments
 *   carried in TXT records.
 * - The inter-query delay (100 ms) is fixed but should be configurable
 *   to tune throughput vs. stealth.
 * - Logging provides detailed timing and queue state information for debugging.
 */
std::string Client::requestMessage()
{
    char buffer[BUFFER_SIZE];
    int nbytes = 0;

    Query query;
    query.setID(0);
    query.setQdCount(1);
    query.setAnCount(0);
    query.setNsCount(0);
    query.setArCount(0);

    dns::debug::log("Client::requestMessage", "Preparing transmission to DNS server " + m_dnsServerAdd + ":" + std::to_string(m_port));

    struct sockaddr_in serv_addr;
    fd_set read_fds;
    FD_ZERO(&read_fds);

#ifdef __linux__
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    inet_aton(m_dnsServerAdd.c_str(), &(serv_addr.sin_addr));
#elif _WIN32
    WSAData data;
    WSAStartup(MAKEWORD(2, 2), &data);
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    serv_addr.sin_port = htons(m_port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr( m_dnsServerAdd.c_str() );
#endif

    dns::debug::log("Client::requestMessage", "UDP socket created; attempting connection test via connect()");

    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    {
        dns::debug::log("Client::requestMessage", "connect() failed; continuing with sendto/recvfrom");
    }
    else
    {
        dns::debug::log("Client::requestMessage", "connect() succeeded for diagnostic connection check");
    }

    size_t iteration = 0;
    auto sessionStart = std::chrono::steady_clock::now();

    // we get all the packet of a message: m_moreMsgToGet
    do
    {
        ++iteration;
        auto iterationStart = std::chrono::steady_clock::now();
        dns::debug::log( "Client::requestMessage", "Iteration " + std::to_string(iteration) + ": awaiting more=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

        // qname transmit our identity
        std::string qname;
        qname = m_secretKeyClientAskData;
        qname += ".";
        qname += generateRandomString(8); // avoid caching
        qname += ".";

        dns::debug::log("Client::requestMessage", "issuing message request with qname '" + qname + "'");
    
        // we add the domain to resolve to ensure we talk to the server
        qname += m_domainToResolve;
        query.setQName(qname);
        // TXT record
        query.setQType(16);
        query.setQClass(1);

        nbytes = query.code(buffer);

        dns::debug::log( "Client::requestMessage", "Encoded query length=" + std::to_string(nbytes) + " bytes for QNAME '" + qname + "'");

        // send udp datza
        int t_len = sizeof(serv_addr);
        int req = sendto(sockfd, buffer, nbytes, 0, (struct sockaddr*) &serv_addr, t_len);
        if(req < 1)
        {
            dns::debug::log("Client::requestMessage", "sendto() failed with return value " + std::to_string(req));
            break;
        }

        auto afterSend = std::chrono::steady_clock::now();
        dns::debug::log( "Client::requestMessage", "Sent " + std::to_string(req) + " bytes to " + m_dnsServerAdd + ":" + std::to_string(m_port) + " (" + dns::debug::formatDuration(afterSend - iterationStart) + " since iteration start)");

        // wait for the replay
        FD_SET(sockfd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 10;
        int selection = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        auto afterSelect = std::chrono::steady_clock::now();

        if(selection < 1)
        {
            if (selection != -1)
            {
                FD_CLR(sockfd, &read_fds);
                dns::debug::log( "Client::requestMessage", "select() timeout after " + dns::debug::formatDuration(afterSelect - afterSend));
                break;
            }
            else
            {
                dns::debug::log("Client::requestMessage", "select() returned error after " + dns::debug::formatDuration(afterSelect - afterSend));
                break;
            }
        }

#ifdef __linux__
        int received = recvfrom(sockfd, &buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#elif _WIN32
        int received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
#endif

        auto afterRecv = std::chrono::steady_clock::now();

        dns::debug::log( "Client::requestMessage", "recvfrom() returned " + std::to_string(received) + " bytes after " + dns::debug::formatDuration(afterRecv - afterSend));

        // all messages are part of the final payload that need to be put together
        // decode extract the data using parse_rdata and the record type received
        Response response;
        response.decode(buffer, received);

        std::string rdata = response.getRdata();

        std::string rdataPreview = rdata.substr(0, 60);
        if(rdata.size() > rdataPreview.size())
            rdataPreview += "...";
        dns::debug::log( "Client::requestMessage", "Received RDATA length=" + std::to_string(static_cast<unsigned long long>(rdata.size())) + " preview='" + rdataPreview + "'");
        
        // reassemble a message from the data extracted from the dns packet
        handleDataReceived(rdata, "serv");

        auto afterHandle = std::chrono::steady_clock::now();
        dns::debug::log( "Client::requestMessage", "Response handling completed in " + dns::debug::formatDuration(afterHandle - afterRecv) + "; fragments remaining=" + std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) +", awaiting more=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

        dns::debug::log("Client::requestMessage", "Applying inter-query delay of 100 ms to avoid flooding");
      
         // TODO make it configurable - Resolvers usually accept ~5–20 qps per client without rate-limiting. Above that, some will throttle or blacklist.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        dns::debug::log( "Client::requestMessage", "Iteration " + std::to_string(iteration) + " total time " + dns::debug::formatDuration(std::chrono::steady_clock::now() - iterationStart));
    }
    while(m_moreMsgToGet);

    auto [clientId, msg] = getMsg();

    dns::debug::log( "Client::requestMessage", "Transmission loop completed after " + dns::debug::formatDuration(std::chrono::steady_clock::now() - sessionStart) + "; remaining fragments=" + std::to_string(static_cast<unsigned long long>(m_msgQueue.size())) + ", awaiting more=" + (m_moreMsgToGet ? std::string("true") : std::string("false")));

#ifdef __linux__
    close(sockfd);
#elif _WIN32
    closesocket(sockfd);
    WSACleanup();
#endif

    dns::debug::log("Client::requestMessage", "Socket closed");

    return msg;
}

