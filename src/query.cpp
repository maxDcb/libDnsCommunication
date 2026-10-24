#include <iostream>
#include <sstream>

#include "query.hpp"

#include <stdio.h>
#include <string.h>

using namespace std;
using namespace dns;


Query::Query() 
: Message(Message::Query) 
{
    m_qName="";
    m_qType=0;
    m_qClass=0;
    m_valid=false;
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


int Query::code(char* buffer)  
{
    if (buffer == nullptr || m_qName.empty() || m_qName.size() > 253)
        return 0;

    size_t labelStart = 0;
    while (labelStart <= m_qName.size())
    {
        const size_t dot = m_qName.find('.', labelStart);
        const size_t labelEnd = dot == std::string::npos ? m_qName.size() : dot;
        const size_t labelLength = labelEnd - labelStart;
        if (labelLength == 0 || labelLength > 63)
            return 0;
        if (dot == std::string::npos)
            break;
        labelStart = dot + 1;
    }

    char* bufferBegin = buffer;

    code_hdr(buffer);
    buffer += HDR_OFFSET;

    encode_qname(buffer, m_qName);

    put16bits(buffer, m_qType);
    put16bits(buffer, m_qClass);

    int size = buffer - bufferBegin;

    return size;
}


void Query::decode(const char* buffer, int size)  
{
    m_valid = false;
    m_qName.clear();
    m_qType = 0;
    m_qClass = 0;

    if (buffer == nullptr || size < static_cast<int>(HDR_OFFSET + 5))
        return;

    const char* end = buffer + size;

    decode_hdr(buffer);
    if (m_qdCount != 1 || isResponse())
        return;
    buffer += HDR_OFFSET;

    if (!decode_qname(buffer, end) || buffer + 4 > end)
        return;

    m_qType = get16bits(buffer);
    m_qClass = get16bits(buffer);
    m_valid = buffer <= end && !m_qName.empty();
}


bool Query::decode_qname(const char*& buffer, const char* end)
{
    m_qName.clear();

    if (buffer >= end)
        return false;

    unsigned int length = static_cast<unsigned char>(*buffer++);
    std::size_t encodedLength = 1;
    while (length != 0) 
    {
        if (length > 63 || buffer + length >= end || encodedLength + length + 1 > 255)
            return false;

        m_qName.append(buffer, length);
        buffer += length;
        encodedLength += length;

        length = static_cast<unsigned char>(*buffer++);
        ++encodedLength;
        if (length != 0) 
            m_qName.append(1,'.');
    }
    return !m_qName.empty();
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
