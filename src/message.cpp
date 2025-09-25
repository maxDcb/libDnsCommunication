#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

#ifdef __linux__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#elif _WIN32

#endif

#include "message.hpp"

using namespace dns;
using namespace std;


Message::Message(Type type) 
: m_qr(type) 
{
    if(m_qr==Message::Query)
        m_rd=1;
    else
        m_rd=0;

    m_id=0;
    m_opcode=0;
    m_aa=0;
    m_tc=0;
    m_ra=0;

    m_rcode=0;
    
    m_qdCount=0;
    m_anCount=0;
    m_nsCount=0;
    m_arCount=0;

    resetEdns();
}


Message::~Message() 
{ 
}


string Message::asString() const  
{
    ostringstream text;
    text << "ID: " << showbase << hex << m_id << endl << noshowbase;
    text << "\tfields: [ QR: " << m_qr << " opCode: " << m_opcode << " ]" << endl;
    text << "\tQDcount: " << m_qdCount << endl;
    text << "\tANcount: " << m_anCount << endl;
    text << "\tNScount: " << m_nsCount << endl;
    text << "\tARcount: " << m_arCount << endl;

    return text.str();
}


void Message::decode_hdr(const char* buffer)  
{
    m_id = get16bits(buffer);

    uint fields = get16bits(buffer);
    m_qr = (fields & QR_MASK) ? 1U : 0U;
    m_opcode = (fields & OPCODE_MASK) >> 11;
    m_aa = (fields & AA_MASK) ? 1U : 0U;
    m_tc = (fields & TC_MASK) ? 1U : 0U;
    m_rd = (fields & RD_MASK) ? 1U : 0U;
    m_ra = (fields & RA_MASK) >> 7;
    m_rcode = fields & RCODE_MASK;

    m_qdCount = get16bits(buffer);
    m_anCount = get16bits(buffer);
    m_nsCount = get16bits(buffer);
    m_arCount = get16bits(buffer);
}


void Message::code_hdr(char* buffer)  
{
    put16bits(buffer, m_id);

    uint16_t fields = 0;
    fields |= (m_qr & 0x1U) << 15;
    fields |= (m_opcode & 0xFU) << 11;
    fields |= (m_aa & 0x1U) << 10;
    fields |= (m_tc & 0x1U) << 9;
    fields |= (m_rd & 0x1U) << 8;
    fields |= (m_ra & 0x1U) << 7;
    fields |= (m_rcode & 0xFU);
    put16bits(buffer, fields);

    put16bits(buffer, m_qdCount);
    put16bits(buffer, m_anCount);
    put16bits(buffer, m_nsCount);
    put16bits(buffer, m_arCount);
}


void Message::log_buffer(const char* buffer, int size)  
{
    ostringstream text;

    text << "Message::log_buffer()" << endl;
    text << "size: " << size << " bytes" << endl;
    text << "---------------------------------" << setfill('0');

    for (int i = 0; i < size; i++) {
        if ((i % 10) == 0) {
            text << endl << setw(2) << i << ": ";
        }
        uchar c = buffer[i];
        text << hex << setw(2) << int(c) << " " << dec;
    }
    text << endl << setfill(' ');
    text << "---------------------------------";

}


int Message::get16bits(const char*& buffer)  
{
    int value = static_cast<uchar> (buffer[0]);
    value = value << 8;
    value += static_cast<uchar> (buffer[1]);
    buffer += 2;

    return value;
}


int Message::get32bits(const char*& buffer)  
{
    int value = static_cast<uchar> (buffer[0]);
    value = value << 8;
    value += static_cast<uchar> (buffer[1]);
    value = value << 8;
    value += static_cast<uchar> (buffer[2]);
    value = value << 8;
    value += static_cast<uchar> (buffer[3]);
    buffer += 4;

    return value;
}


void Message::put16bits(char*& buffer, uint value) const
{
    buffer[0] = (value & 0xFF00) >> 8;
    buffer[1] = value & 0xFF;
    buffer += 2;
}


void Message::put32bits(char*& buffer, ulong value) const
{
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
    buffer += 4;
}

void Message::resetEdns()
{
    m_edns.present = false;
    m_edns.udpPayloadSize = 512;
    m_edns.extendedRcode = 0;
    m_edns.version = 0;
    m_edns.flags = 0;
    m_edns.data.clear();
}

void Message::enableEdns(uint16_t udpPayloadSize)
{
    m_edns.present = true;
    m_edns.udpPayloadSize = udpPayloadSize;
    if (m_arCount == 0)
        m_arCount = 1;
}

void Message::disableEdns()
{
    resetEdns();
}

void Message::skipDomain(const char*& buffer, const char* end)
{
    while (buffer < end)
    {
        uint8_t length = static_cast<uint8_t>(*buffer++);
        if (length == 0)
            return;

        if ((length & 0xC0) == 0xC0)
        {
            if (buffer < end)
                ++buffer;
            return;
        }

        if (buffer + length > end)
        {
            buffer = end;
            return;
        }

        buffer += length;
    }
}

void Message::encodeEdns(char*& buffer) const
{
    if (!m_edns.present)
        return;

    *buffer++ = 0;
    put16bits(buffer, 41);
    put16bits(buffer, m_edns.udpPayloadSize);

    uint32_t ttl = (static_cast<uint32_t>(m_edns.extendedRcode) << 24) |
                   (static_cast<uint32_t>(m_edns.version) << 16) |
                   static_cast<uint32_t>(m_edns.flags);
    put32bits(buffer, ttl);

    uint16_t rdlength = static_cast<uint16_t>(m_edns.data.size());
    put16bits(buffer, rdlength);
    if (rdlength > 0)
    {
        std::memcpy(buffer, m_edns.data.data(), rdlength);
        buffer += rdlength;
    }
}

bool Message::decodeEdns(const char*& buffer, const char* end)
{
    skipDomain(buffer, end);
    if (buffer >= end)
    {
        buffer = end;
        return false;
    }

    if (buffer + 2 > end)
    {
        buffer = end;
        return false;
    }
    uint16_t type = static_cast<uint16_t>(get16bits(buffer));

    if (buffer + 2 > end)
    {
        buffer = end;
        return false;
    }
    uint16_t udpPayload = static_cast<uint16_t>(get16bits(buffer));

    if (buffer + 4 > end)
    {
        buffer = end;
        return false;
    }
    uint32_t ttl = static_cast<uint32_t>(get32bits(buffer));

    if (buffer + 2 > end)
    {
        buffer = end;
        return false;
    }
    uint16_t rdlength = static_cast<uint16_t>(get16bits(buffer));

    size_t remaining = buffer < end ? static_cast<size_t>(end - buffer) : 0U;
    size_t available = std::min(static_cast<size_t>(rdlength), remaining);

    if (type == 41)
    {
        m_edns.present = true;
        m_edns.udpPayloadSize = udpPayload;
        m_edns.extendedRcode = static_cast<uint8_t>((ttl >> 24) & 0xFF);
        m_edns.version = static_cast<uint8_t>((ttl >> 16) & 0xFF);
        m_edns.flags = static_cast<uint16_t>(ttl & 0xFFFF);
        m_edns.data.assign(buffer, buffer + available);
    }

    buffer += available;
    if (available < rdlength)
    {
        buffer = end;
    }

    return type == 41;
}
