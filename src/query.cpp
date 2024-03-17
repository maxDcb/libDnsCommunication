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