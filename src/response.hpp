#pragma once

#include "message.hpp"


namespace dns 
{

class Response : public Message 
{
public:

    enum Code { Ok=0, FormatError, ServerFailure, NameError, NotImplemented, Refused };

    Response();
    ~Response();

    int code(char* buffer);
    void decode(const char* buffer, int size);

    std::string asString() const;

    void setRCode(Code code) { m_rcode = code; }
    void setName(const std::string& value) { m_name = value; }
    void setType(const uint value) { m_type = value; }
    void setClass(const uint value) { m_class = value; }
    void setTtl(const ulong value) { m_ttl = value; }
    void setRdLength(const uint value) { m_rdLength = value; }
    void setRdata(const std::string& value) { m_rdata = value; }

    const std::string& getRdata() { return m_rdata; }
    const std::string& getName() const { return m_name; }
    
private:
    std::string m_name;
    uint m_type;
    uint m_class;
    ulong m_ttl;
    uint m_rdLength;
    std::string m_rdata;

    void decode_domain(const char*& buffer, std::string& domain, const char* begin, const char* end);
    void code_domain(char*& buffer, const std::string& domain);
};

}


