#include <iostream>
#include <algorithm>
#include <sstream>

#include "query.hpp"

#include <cstring>

using namespace std;
using namespace dns;


Query::Query()
: Message(Message::Query)
, m_useEdns0(false)
, m_ednsUdpPayloadSize(kDefaultEdnsUdpPayloadSize)
, m_ednsExtendedRcode(0)
, m_ednsVersion(0)
, m_ednsFlags(0)
{
    m_qName="";
    m_qType=0;
    m_qClass=0;

    enableEdns0(kDefaultEdnsUdpPayloadSize);
}


Query::~Query() 
{    
}


string Query::asString() const
{
    ostringstream text;
    text << endl << "QUERY { ";
    text << Message::asString();
    text << "\tQname: " << m_qName << endl;
    text << "\tQtype: " << m_qType << endl;
    text << "\tQclass: " << m_qClass;
    text << " }" << dec;

    return text.str();
}


std::string Query::encode() const
{
    size_t labelCount = m_qName.empty() ? 1 :
        static_cast<size_t>(std::count(m_qName.begin(), m_qName.end(), '.') + 1);
    size_t qnameSize = m_qName.size() + labelCount + 1;
    size_t totalSize = HDR_OFFSET + qnameSize + 4; // qtype + qclass

    size_t additionalSize = 0;
    if (m_useEdns0)
        additionalSize += 11; // root label + type + class + ttl + rdlen

    std::string buffer(totalSize + additionalSize, '\0');

    Query* self = const_cast<Query*>(this);

    uint16_t originalArCount = self->m_arCount;
    self->m_arCount = m_useEdns0 ? 1 : 0;

    char* headerPtr = buffer.data();
    self->code_hdr(headerPtr);

    char* ptr = buffer.data() + HDR_OFFSET;
    self->encode_qname(ptr, m_qName);
    self->put16bits(ptr, m_qType);
    self->put16bits(ptr, m_qClass);

    if (m_useEdns0)
    {
        *ptr++ = 0; // root label
        self->put16bits(ptr, 41); // OPT record

        uint16_t payloadSize = std::max<uint16_t>(static_cast<uint16_t>(512), m_ednsUdpPayloadSize);
        self->put16bits(ptr, payloadSize);

        uint32_t ttl = (static_cast<uint32_t>(m_ednsExtendedRcode) << 24) |
                       (static_cast<uint32_t>(m_ednsVersion) << 16) |
                       static_cast<uint32_t>(m_ednsFlags);
        self->put32bits(ptr, ttl);
        self->put16bits(ptr, 0); // no EDNS options
    }

    self->m_arCount = originalArCount;

    buffer.resize(static_cast<size_t>(ptr - buffer.data()));
    return buffer;
}

int Query::code(char* buffer)
{
    std::string encoded = encode();
    std::memcpy(buffer, encoded.data(), encoded.size());
    return static_cast<int>(encoded.size());
}


void Query::decode(const char* buffer, int size)
{
    const char* begin = buffer;
    const char* end = buffer + size;

    decode_hdr(buffer);
    const char* cursor = begin + HDR_OFFSET;

    decode_qname(cursor);

    m_qType = get16bits(cursor);
    m_qClass = get16bits(cursor);

    m_useEdns0 = false;
    m_ednsUdpPayloadSize = kDefaultEdnsUdpPayloadSize;
    m_ednsExtendedRcode = 0;
    m_ednsVersion = 0;
    m_ednsFlags = 0;

    for (uint i = 0; i < m_arCount && cursor < end; ++i)
    {
        while (cursor < end)
        {
            uint8_t len = static_cast<uint8_t>(*cursor++);
            if ((len & 0xC0) == 0xC0)
            {
                if (cursor < end)
                    ++cursor; // skip pointer offset
                break;
            }
            if (len == 0)
                break;
            if (cursor + len > end)
            {
                cursor = end;
                break;
            }
            cursor += len;
        }

        if (cursor + 10 > end)
        {
            cursor = end;
            break;
        }

        uint16_t type = get16bits(cursor);
        uint16_t udpSize = static_cast<uint16_t>(get16bits(cursor));
        uint32_t ttl = static_cast<uint32_t>(get32bits(cursor));
        uint16_t rdlength = static_cast<uint16_t>(get16bits(cursor));

        if (cursor + rdlength > end)
        {
            rdlength = static_cast<uint16_t>(std::max<long>(0, end - cursor));
        }

        if (type == 41)
        {
            m_useEdns0 = true;
            m_ednsUdpPayloadSize = std::max<uint16_t>(static_cast<uint16_t>(512), udpSize);
            m_ednsExtendedRcode = static_cast<uint8_t>((ttl >> 24) & 0xFF);
            m_ednsVersion = static_cast<uint8_t>((ttl >> 16) & 0xFF);
            m_ednsFlags = static_cast<uint16_t>(ttl & 0xFFFF);
        }

        cursor += rdlength;
    }
}


void Query::decode_qname(const char*& buffer)
{
    m_qName.clear();

    int length = *buffer++;
    while (length != 0) 
    {
        for (int i = 0; i < length; i++) 
        {
            char c = *buffer++;
            m_qName.append(1, c);
        }
        
        length = *buffer++;
        if (length != 0) 
            m_qName.append(1,'.');
    }
}


void Query::encode_qname(char*& buffer, const std::string& domain)
{
    int start(0), end; // indexes

    while ((end = domain.find('.', start)) != string::npos) {

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

void Query::enableEdns0(uint16_t udpPayloadSize)
{
    m_useEdns0 = true;
    if (udpPayloadSize < 512)
        udpPayloadSize = 512;
    m_ednsUdpPayloadSize = udpPayloadSize;
    m_ednsExtendedRcode = 0;
    m_ednsVersion = 0;
    m_ednsFlags = 0;
    m_arCount = 1;
}

void Query::disableEdns0()
{
    m_useEdns0 = false;
    m_ednsUdpPayloadSize = 512;
    m_ednsExtendedRcode = 0;
    m_ednsVersion = 0;
    m_ednsFlags = 0;
    m_arCount = 0;
}