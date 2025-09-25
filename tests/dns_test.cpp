#include <algorithm>
#include <cassert>
#include <string>
#include <utility>

#include "dns.hpp"
#include "dnsPacker.hpp"

using namespace dns;

namespace {

class DnsHarness : public Dns {
public:
    DnsHarness(const std::string& domain, const std::string& id)
        : Dns(domain, id) {}

    void queueMessage(const std::string& msg, const std::string& clientId, int qType)
    {
        setMsg(msg, clientId);
        splitPacket(qType, clientId);
    }

    bool hasQueuedFragments(const std::string& clientId) const
    {
        auto it = m_msgQueue.find(clientId);
        return it != m_msgQueue.end() && !it->second.empty();
    }

    std::string popFragment(const std::string& clientId)
    {
        auto& queue = m_msgQueue[clientId];
        std::string fragment = queue.front();
        queue.pop();
        return fragment;
    }

    void ingest(const std::string& payload, const std::string& clientId)
    {
        handleDataReceived(payload, clientId);
    }

    std::pair<std::string, std::string> takeComplete()
    {
        return getMsg();
    }
};

} // namespace

int main()
{
    const std::string domain = "example.com";
    const std::string clientIdentity = "cli";
    const std::string serverIdentity = "serv";
    const std::string clientMsg = "ping from client";
    const std::string serverMsg = "pong from server";

    DnsHarness clientHarness(domain, "aa.");
    DnsHarness serverHarness(domain, "");

    // Client prepares data destined for the server (encoded inside CNAME queries)
    clientHarness.queueMessage(clientMsg, serverIdentity, 5);

    while (clientHarness.hasQueuedFragments(serverIdentity))
    {
        std::string fragmentHex = clientHarness.popFragment(serverIdentity);
        std::string qnameData = addDotEvery62Chars(fragmentHex);
        serverHarness.ingest(qnameData, clientIdentity);
    }

    auto [serverClientId, serverReceived] = serverHarness.takeComplete();
    assert(serverClientId == clientIdentity);
    assert(serverReceived == clientMsg);

    // Server prepares data destined for the client (delivered via TXT responses)
    serverHarness.queueMessage(serverMsg, clientIdentity, 16);

    while (serverHarness.hasQueuedFragments(clientIdentity))
    {
        std::string responsePayload = serverHarness.popFragment(clientIdentity);
        clientHarness.ingest(responsePayload, serverIdentity);
    }

    auto [clientServerId, clientReceived] = clientHarness.takeComplete();
    assert(clientServerId == serverIdentity);
    assert(clientReceived == serverMsg);

    return 0;
}
