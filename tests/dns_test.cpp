#include <cassert>
#include <string>

#include "server.hpp"
#include "client.hpp"
#include "query.hpp"
#include "response.hpp"
#include "dnsPacker.hpp"

using namespace dns;

class ClientEx : public Client {
public:
    using Client::Client;
    std::string popMessage() { auto m = m_msgQueue.front(); m_msgQueue.pop(); return m; }
    void handle(const std::string& r) { handleResponse(r); }
};

class ServerEx : public Server {
public:
    using Server::Server;
    void addQName(const std::string& q) { addReceivedQName(q); }
    std::string popMessage() { auto m = m_msgQueue.front(); m_msgQueue.pop(); return m; }
};

int main() {
    const std::string domain = "example.com";
    const std::string clientMsg = "ping from client";
    const std::string serverMsg = "pong from server";

    ServerEx server(0, domain);
    server.setMsg(serverMsg);

    ClientEx client("127.0.0.1", domain, 0);
    client.setMsg(clientMsg);

    std::string qHex = client.popMessage();
    std::string qname = addDotEvery62Chars(qHex) + "." + domain;

    Query query;
    query.setID(0);
    query.setQName(qname);
    query.setQType(16);
    query.setQClass(1);

    std::string serverHex = server.popMessage();

    Response response;
    response.setRCode(Response::Ok);
    response.setRdLength(serverHex.size()+2);
    response.setID(query.getID());
    response.setQdCount(1);
    response.setAnCount(1);
    response.setName(query.getQName());
    response.setType(query.getQType());
    response.setClass(query.getQClass());
    response.setRdata(serverHex);

    server.addQName(qname);
    std::string serverReceived = server.getMsg();

    client.handle(response.getRdata());
    std::string clientReceived = client.getMsg();

    if (serverReceived != clientMsg) return 1;
    if (clientReceived != serverMsg) return 1;
    return 0;
}
