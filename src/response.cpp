#include <iostream>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <set>

#ifdef __linux__

#include <arpa/inet.h>

#elif _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#endif

#include "message.hpp"
#include "response.hpp"

using namespace std;
using namespace dns;


Response::Response() 
: Message(Message::Response) 
{ 
    m_name="";
    m_type=0;
    m_class=0;
    m_ttl=0;
    m_rdLength=0;
    m_rdata="";
}


Response::~Response() 
{ 
}


string Response::asString() const 
{
    ostringstream text;
    text << endl << "RESPONSE { ";
    text << Message::asString();

    text << "\tname: " << m_name << endl;
    text << "\ttype: " << m_type << endl;
    text << "\tclass: " << m_class << endl;
    text << "\tttl: " << m_ttl << endl;
    text << "\trdLength: " << m_rdLength << endl;
    text << "\trdata: " << m_rdata << " }" << dec;

    return text.str();
}


void Response::decode(const char* buffer, int size)
{
    const char* begin = buffer;
    const char* end = buffer + size;

    decode_hdr(buffer);
    buffer += HDR_OFFSET;

    // query
    std::string respDom;
    decode_domain(buffer, respDom, begin, end);
    m_name = respDom;
    m_type = get16bits(buffer);
    m_class = get16bits(buffer);

    // answer
    decode_domain(buffer, respDom, begin, end);
    m_name = respDom;
    uint type_ = get16bits(buffer);
    uint class_ = get16bits(buffer);
    m_ttl = get32bits(buffer);

    if(type_ == 16)
    {
        m_rdLength = get16bits(buffer);
        // skip la size ?
        buffer++;
        for (int i = 0; i < m_rdLength; i++) 
        {
            char c = *buffer++;
            m_rdata.append(1, c);
        }
    }
    else
    {
        // std::cout << "TODO: decode type diff than txt" << std::endl;
    }
}


int Response::code(char* buffer) 
{
    char* bufferBegin = buffer;

    code_hdr(buffer);
    buffer += HDR_OFFSET;

    // Code Question section
    code_domain(buffer, m_name);
    put16bits(buffer, m_type);
    put16bits(buffer, m_class);

    // Code Answer section
    put16bits(buffer, 49164);
    // code_domain(buffer, m_name);
    put16bits(buffer, m_type);
    put16bits(buffer, m_class);
    put32bits(buffer, m_ttl);
    put16bits(buffer, m_rdLength);
    code_domain(buffer, m_rdata);

    int size = buffer - bufferBegin;
    log_buffer(bufferBegin, size);

    return size;
}


void Response::decode_domain(const char*& buffer, std::string& domain,
                             const char* begin, const char* end)
{
    domain.clear();

    const char* cur = buffer;
    bool jumped = false;
    std::set<const char*> visited;

    while (cur < end) {
        uint8_t len = static_cast<uint8_t>(*cur);

        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= end) { buffer = end; return; }
            uint16_t offset = ((len & 0x3F) << 8) | static_cast<uint8_t>(cur[1]);
            const char* ptr = begin + offset;
            if (ptr < begin || ptr >= end || visited.count(ptr)) {
                buffer = end;
                return;
            }
            visited.insert(ptr);
            if (!jumped) {
                buffer = cur + 2;
                jumped = true;
            }
            cur = ptr;
            continue;
        }

        if (len == 0) {
            ++cur;
            if (!jumped) buffer = cur;
            return;
        }

        ++cur;
        if (cur + len > end) { buffer = end; return; }
        domain.append(cur, len);
        cur += len;
        if (*cur != 0) domain.push_back('.');
    }

    buffer = end;
}


void Response::code_domain(char*& buffer, const std::string& domain) 
{
    int start(0), end; // indexes

    while ((end = domain.find('.', start)) != string::npos) 
    {

        *buffer++ = end - start; // label length octet
        for (int i=start; i<end; i++) {

            *buffer++ = domain[i]; // label octets
        }
        start = end + 1; // Skip '.'
    }

    *buffer++ = domain.size() - start; // last label length octet
    for (int i=start; i<domain.size(); i++) {

        *buffer++ = domain[i]; // last label octets
    }

    *buffer++ = 0;
}