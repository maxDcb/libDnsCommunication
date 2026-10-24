#include <cassert>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "client.hpp"
#include "server.hpp"

using namespace dns;

namespace
{
std::pair<std::string, std::string> waitForMessage(Server& server)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto message = server.getAvailableMessage();
        if (!message.second.empty())
            return message;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return {};
}

void sendMalformedDatagram(int port)
{
#ifdef _WIN32
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    SOCKET socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(socketFd != INVALID_SOCKET);
#else
    int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(socketFd >= 0);
#endif

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const char value = 0;
    assert(sendto(socketFd, &value, 1, 0,
                  reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 1);

#ifdef _WIN32
    closesocket(socketFd);
    WSACleanup();
#else
    close(socketFd);
#endif
}
}

int main()
{
    Server server(0, "contract.test");
    assert(server.launch());
    assert(server.isRunning());
    assert(server.getPort() > 0);

    // A second listener on the same endpoint fails cleanly and remains safe to stop.
    Server conflicting(server.getPort(), "contract.test");
    assert(!conflicting.launch());
    assert(!conflicting.isRunning());
    conflicting.stop();

    // A short datagram must not terminate the server worker.
    sendMalformedDatagram(server.getPort());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(server.isRunning());

    Client client("127.0.0.1", "contract.test", server.getPort());
    const std::string upload(700, 'U');
    assert(client.sendMessage(upload));

    auto [clientId, receivedUpload] = waitForMessage(server);
    assert(!clientId.empty());
    assert(receivedUpload == upload);

    const std::string firstDownload(700, 'A');
    const std::string secondDownload(700, 'B');
    assert(server.setMessageToSend(firstDownload, clientId));
    assert(server.setMessageToSend(secondDownload, clientId));

    assert(client.requestMessage() == firstDownload);
    assert(client.requestMessage() == secondDownload);
    assert(client.requestMessage().empty());

    server.stop();
    assert(!server.isRunning());

    // Retrying the same application payload after a transport failure resumes
    // its fragment queue instead of enqueueing a duplicate message.
    Client retryingClient("127.0.0.1", "contract.test", server.getPort());
    const std::string retriedUpload(300, 'R');
    assert(!retryingClient.sendMessage(retriedUpload));
    assert(server.launch());
    assert(retryingClient.sendMessage(retriedUpload));
    auto retried = waitForMessage(server);
    assert(retried.second == retriedUpload);
    assert(server.getAvailableMessage().second.empty());

    server.stop();
    server.stop();
    return 0;
}
