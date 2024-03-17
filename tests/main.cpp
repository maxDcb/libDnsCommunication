#include <iostream>

#include "server.hpp"
#include "client.hpp"


using namespace std;
using namespace dns;


int main(int argc, char** argv) 
{
    std::string type;
    type.assign(argv[1]);

    if(type=="server")
    {
        if (argc < 3)
        {
            std::cout << "Usage ./DnsServer server ns.domain.com" << std::endl;
            return -1;
        }

        int port = 53;
        if (port < 1 || port > 65535) 
        {
            return -1;   
        }

        std::string domainToResolve;
        domainToResolve.assign(argv[2]);

        Server server(port, domainToResolve);
        server.launch();

        std::string test = "elevator puzzle umbrella sparkle facade galaxy misty blossom horizon thunder kitten embrace wanderer velvet whisper journey melody prism twilight harmony radiant tranquility paradise reflection serendipity breeze blossom moonlight tranquility radiant whisper serendipity horizon";

        std::cout << test << std::endl;
        server.setMsg(test);

        while(1)
        {
            std::string result = server.getMsg();
            std::cout << "result " << result << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }

        server.stop();

    }
    else if(type=="client")
    {
        if (argc < 5)
        {
            std::cout << "Usage ./DnsServer client 8.8.8.8 ns.domain.com \"msg to send\"" << std::endl;
            return -1;
        }

        std::string dnsServerAdd;
        dnsServerAdd.assign(argv[2]);

        std::string host;
        host.assign(argv[3]);

        std::string msg;
        msg.assign(argv[4]);

        Client client(dnsServerAdd, host);
        client.sendMessage(msg);

        std::string result = client.getMsg();
        std::cout << "result " << result << std::endl; 
        while(!result.empty())
        {
            result = client.getMsg();
            std::cout << "result " << result << std::endl;
        }
    }

    return 0;
}
