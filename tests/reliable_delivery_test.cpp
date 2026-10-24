#include <cassert>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "dns.hpp"
#include "server.hpp"

using namespace dns;

namespace
{
class DnsHarness : public Dns
{
public:
    DnsHarness() : Dns("example.test", "") {}

    bool queue(const std::string& message, const std::string& clientId)
    {
        if (!setMsg(message, clientId))
            return false;
        splitPacket(16, clientId);
        return true;
    }

    std::string peek(const std::string& clientId)
    {
        return peekQueuedFragment(clientId);
    }

    std::optional<FragmentIdentity> identity(const std::string& clientId)
    {
        return queuedFragmentIdentity(clientId);
    }

    bool acknowledge(const std::string& clientId,
                     const std::string& session,
                     int index)
    {
        return acknowledgeQueuedFragment(clientId, session, index);
    }

    std::optional<FragmentIdentity> ingest(const std::string& fragment,
                                           const std::string& clientId)
    {
        return handleDataReceived(fragment, clientId);
    }

    std::pair<std::string, std::string> take()
    {
        return getMsg();
    }
};

class ServerHarness : public Server
{
public:
    ServerHarness() : Server(0, "example.test") {}

    std::string request(const std::string& data, const std::string& clientId)
    {
        Query query;
        query.setID(1);
        query.setQdCount(1);
        query.setQName(data + "." + clientId + ".example.test");
        query.setQType(16);
        query.setQClass(1);

        Response response;
        prepareResponse(query, response);
        assert(response.getRCode() == Response::Ok);
        return response.getRdata();
    }
};

FragmentIdentity fragmentIdentity(const std::string& encoded)
{
    std::string decoded;
    assert(tryHexToString(encoded, decoded));
    const auto packet = nlohmann::json::parse(decoded);
    return {packet.at("s").get<std::string>(),
            packet.at("k").get<int>(),
            packet.at("n").get<int>()};
}
}

int main()
{
    const std::string clientId = "client1";
    const std::string message(600, 'R');
    DnsHarness sender;
    DnsHarness receiver;

    assert(sender.queue(message, clientId));

    std::vector<std::string> fragments;
    while (true)
    {
        const std::string firstRead = sender.peek(clientId);
        if (firstRead.empty())
            break;

        // Reading a fragment does not consume it. A lost UDP response therefore
        // results in the exact same fragment being offered again.
        assert(sender.peek(clientId) == firstRead);

        const auto fragmentId = sender.identity(clientId);
        assert(fragmentId);
        assert(!sender.acknowledge(clientId, fragmentId->session,
                                   fragmentId->index + 1));
        assert(sender.peek(clientId) == firstRead);

        fragments.push_back(firstRead);
        assert(sender.acknowledge(clientId, fragmentId->session,
                                  fragmentId->index));
    }

    assert(fragments.size() > 1);

    // Duplicates and reversed delivery remain idempotent and reassemble once.
    for (auto it = fragments.rbegin(); it != fragments.rend(); ++it)
    {
        assert(receiver.ingest(*it, clientId));
        assert(receiver.ingest(*it, clientId));
    }

    auto completed = receiver.take();
    assert(completed.first == clientId);
    assert(completed.second == message);
    assert(receiver.take().second.empty());

    // Invalid encodings and invalid fragment metadata are rejected without
    // creating a completed message or throwing.
    assert(!receiver.ingest("not-hex", clientId));
    assert(!receiver.ingest("7B226D223A2278222C2273223A2261222C226B223A322C226E223A317D",
                            clientId));
    assert(receiver.take().second.empty());

    // Replaying a final ACK (for example because its noData response was lost)
    // must not expose the first fragment of the following application message.
    ServerHarness server;
    assert(server.setMessageToSend(std::string(600, 'A'), clientId));
    assert(server.setMessageToSend(std::string(600, 'B'), clientId));

    std::string response = server.request("ask.none.0.cache", clientId);
    FragmentIdentity lastFragment;
    while (response != "noData")
    {
        lastFragment = fragmentIdentity(response);
        response = server.request("ask." + lastFragment.session + "." +
                                  std::to_string(lastFragment.index) + ".cache",
                                  clientId);
    }
    const std::string finalAck = "ask." + lastFragment.session + "." +
                                 std::to_string(lastFragment.index) + ".cache";
    assert(server.request(finalAck, clientId) == "noData");
    assert(server.request("ask.none.0.next", clientId) != "noData");
    return 0;
}
