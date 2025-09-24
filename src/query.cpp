#include <iostream>
#include <algorithm>
#include <sstream>

#include "query.hpp"

#include <cstring>

using namespace std;
using namespace dns;


Query::Query() 
: Message(Message::Query) 
{
    m_qName="";
    m_qType=0;
    m_qClass=0;
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

    std::string buffer(totalSize, '\0');

    Query* self = const_cast<Query*>(this);

    char* headerPtr = buffer.data();
    self->code_hdr(headerPtr);

    char* ptr = buffer.data() + HDR_OFFSET;
    self->encode_qname(ptr, m_qName);
    self->put16bits(ptr, m_qType);
    self->put16bits(ptr, m_qClass);

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
    // log_buffer(buffer, size);

    decode_hdr(buffer);
    buffer += HDR_OFFSET;
    
    decode_qname(buffer);

    m_qType = get16bits(buffer);
    m_qClass = get16bits(buffer);
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