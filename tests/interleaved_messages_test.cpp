#include <algorithm>
#include <cassert>
#include <string>
#include <utility>
#include <vector>

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

    bool hasFragments(const std::string& clientId) const
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
    const std::string serverIdentity = "serv";
    const std::string clientA = "clientA";
    const std::string clientB = "clientB";

    // Messages large enough to require fragmentation
    std::string msgA(200, 'A');
    std::string msgB(200, 'B');

    DnsHarness clientHarnessA(domain, "aa.");
    DnsHarness clientHarnessB(domain, "bb.");
    DnsHarness serverHarness(domain, "");

    clientHarnessA.queueMessage(msgA, serverIdentity, 5);
    clientHarnessB.queueMessage(msgB, serverIdentity, 5);

    std::vector<std::pair<std::string, std::string>> interleavedFragments;

    while (clientHarnessA.hasFragments(serverIdentity) || clientHarnessB.hasFragments(serverIdentity))
    {
        if (clientHarnessA.hasFragments(serverIdentity))
        {
            std::string fragment = clientHarnessA.popFragment(serverIdentity);
            interleavedFragments.emplace_back(clientA, addDotEvery62Chars(fragment));
        }
        if (clientHarnessB.hasFragments(serverIdentity))
        {
            std::string fragment = clientHarnessB.popFragment(serverIdentity);
            interleavedFragments.emplace_back(clientB, addDotEvery62Chars(fragment));
        }
    }

    for (const auto& [clientId, payload] : interleavedFragments)
    {
        serverHarness.ingest(payload, clientId);
    }

    std::vector<std::pair<std::string, std::string>> received;
    while (true)
    {
        auto [clientId, msg] = serverHarness.takeComplete();
        if (msg.empty())
            break;
        received.emplace_back(clientId, msg);
    }

    assert(received.size() == 2);

    bool hasA = false;
    bool hasB = false;
    for (const auto& [clientId, msg] : received)
    {
        if (clientId == clientA && msg == msgA)
            hasA = true;
        else if (clientId == clientB && msg == msgB)
            hasB = true;
    }

    assert(hasA && hasB);
    return 0;
}
