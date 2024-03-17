#include <iostream>
#include <sstream>
#include <iomanip>

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
    m_qr = fields & QR_MASK;
    m_opcode = fields & OPCODE_MASK;
    m_aa = fields & AA_MASK;
    m_tc = fields & TC_MASK;
    m_rd = fields & RD_MASK;
    m_ra = fields & RA_MASK;

    m_qdCount = get16bits(buffer);
    m_anCount = get16bits(buffer);
    m_nsCount = get16bits(buffer);
    m_arCount = get16bits(buffer);
}


void Message::code_hdr(char* buffer)  
{
    put16bits(buffer, m_id);

    int fields = 0;
    fields += (m_qr << 15);
    // fields += (m_opcode << 14);
    fields += (m_aa << 10);
    fields += (m_tc << 9);
    fields += (m_rd << 8);
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


void Message::put16bits(char*& buffer, uint value)  
{
    buffer[0] = (value & 0xFF00) >> 8;
    buffer[1] = value & 0xFF;
    buffer += 2;
}


void Message::put32bits(char*& buffer, ulong value)  
{
    buffer[0] = (value & 0xFF000000) >> 24;
    buffer[1] = (value & 0xFF0000) >> 16;
    buffer[2] = (value & 0xFF00) >> 16;
    buffer[3] = (value & 0xFF) >> 16;
    buffer += 4;
}
