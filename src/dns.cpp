#include <iostream>
#include <cstring>
#include <string>

#include <algorithm>
#include <cctype>
#include <string_view>

#include <json.hpp>
#include "dns.hpp"


using namespace std;
using namespace dns;

using json = nlohmann::json;


Dns::Dns(const std::string& domain)
: m_domainToResolve(domain)
{ 
    m_maxMessageSize = getMaxMsgLen(domain);
    m_moreMsgToGet = false;

    std::cout << "maxMessageSize " << std::to_string(m_maxMessageSize) << std::endl;
}


Dns::~Dns() 
{ 
}

#undef min
void Dns::setMsg(const std::string& msg)
{
    const std::lock_guard<std::mutex> lock(m_mutex);   

    std::string sessionId = generateRandomString(5);

    json packetJson;
    packetJson += json::object_t::value_type("m", msg);
    packetJson += json::object_t::value_type("s", sessionId);
    packetJson += json::object_t::value_type("n", 1);
    packetJson += json::object_t::value_type("k", 0);
    std::string packet = packetJson.dump();

    // TODO should have a session ID to handle multi sessions
    if(packet.size() > m_maxMessageSize)
    {
        int nbMaxMessage = msg.size()/m_maxMessageSize*2;

        // std::cout << msg.size() << std::endl;
        // std::cout << m_maxMessageSize << std::endl;
        // std::cout << nbMaxMessage << std::endl;

        std:vector<json> messages;

        int indxMsg=0;
        packetJson["m"]="";
        packetJson["n"]=nbMaxMessage;
        packetJson["k"]=indxMsg;
        packet = packetJson.dump();

        int maxLength = m_maxMessageSize-packet.size();
        int length = msg.length();
        int startPos = 0;
        while (startPos < length) 
        {
            int chunkSize = std::min(maxLength, int(length - startPos));
            std::string tmp = msg.substr(startPos, chunkSize);
            packetJson["k"]=indxMsg;
            packetJson["m"]=tmp;
            packet = packetJson.dump();
            messages.push_back(packetJson);
            indxMsg++;
            
            startPos += chunkSize;
        }

        for(int i=0; i<messages.size(); i++)
        {
            messages[i]["n"]=messages.size();

            // std::cout << "packet " << messages[i].dump().size() << " " << messages[i].dump() << std::endl;

            std::string msgHex = stringToHex(messages[i].dump());
            m_msgQueue.push(msgHex);
        }
    }
    // need only one message
    else
    {
        std::string msgHex = stringToHex(packet);

        m_msgQueue.push(msgHex);
    }
}


void Dns::handleResponse(const std::string& rdata)
{
    // std::string msg = rdata.substr(0, rdata.length() - m_domainToResolve.size() - 1); // to account for the final .
    std::string msg = rdata;

    // std::cout << "handleResponse:: rdata " << rdata << std::endl;

    if(startsWith(rdata, "admin"))
        return;

    // Remove all the dots
    auto noDot = std::remove(msg.begin(), msg.end(), '.');
    msg.erase(noDot, msg.end());

    // decode hex
    std::string msgReceived = hexToString(msg);

    // std::cout << "handleResponse:: msgReceived " << msgReceived << std::endl;

    // std::cout << "handleResponse:: FUCKKKK " << msgReceived << std::endl;

    size_t lastBracePos = msgReceived.find_last_of('}');
    if (lastBracePos == std::string::npos) 
        return;
    
    json packetJson;
    try 
    {
        packetJson = json::parse(msgReceived.substr(0, lastBracePos+1));
    } 
    catch (const std::exception& e)
    {
        return;
        // Catching all exceptions derived from std::exception
    } 
    catch (...) 
    {
        return;
        // Catching all other exceptions not derived from std::exception
    }
    
    // std::cout << "handleResponse:: packetJson " << packetJson << std::endl;

    std::string session = packetJson["s"];

    m_moreMsgToGet=true;    
    bool isNewSession=false;
    int k = packetJson["k"].get<int>();
    int n = packetJson["n"].get<int>();
    for(int i=0; i<m_msgReceived.size(); i++)
    {
        if(m_msgReceived[i].id==session)
        {
            isNewSession=true;
            m_msgReceived[i].data.append(packetJson["m"]);
            if(k==n-1)
            {
                m_msgReceived[i].isFull=true;
                m_moreMsgToGet=false;
            }

            // std::cout << "session " << session << std::endl;
            // std::cout << "m_msgReceived[i].data " << m_msgReceived[i].data << std::endl;
            // std::cout << "m_msgReceived[i].isFull " << m_msgReceived[i].isFull << std::endl;
        }
    }

    if(isNewSession==false)
    {
        Packet packet;
        packet.id.append(session);
        packet.data.append(packetJson["m"]);
        if(k==n-1)
        {
           packet.isFull=true;
           m_moreMsgToGet=false;
        }
        else
        {
            packet.isFull=false;
            m_moreMsgToGet=true;
        }
        m_msgReceived.push_back(packet);

        // std::cout << "packet.id " << packet.id << std::endl;
        // std::cout << "packet.data " << packet.data << std::endl;
        // std::cout << "packet.isFull " << packet.isFull << std::endl;
    }
}


// return the first message that is available, or an empty string if no message is avalable
std::string Dns::getMsg()
{    
    // only for server, for client handleResponse is executed on each process and qnameTmp is empty
    std::unique_lock<std::mutex> lock(m_mutex);   

    std::vector<std::string> qnameTmp = m_qnameReceived;
    m_qnameReceived.clear();

    lock.unlock();

    for(int i=0; i<qnameTmp.size(); i++)
        handleResponse(qnameTmp[i]);
    
    std::string result;
    for (auto it = m_msgReceived.begin(); it != m_msgReceived.end();) 
    {
        if (it->isFull) 
        {
            result = it->data;
            it = m_msgReceived.erase(it);
            break;
        } 
        else 
        {
            ++it;
        }
    }

    return result;
}