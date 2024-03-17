#pragma once

#include <string>

#include "message.hpp"


namespace dns 
{

class Query : public Message 
{
public:

    Query();
    ~Query();

    int code(char* buffer);

    void decode(const char* buffer, int size);

    std::string asString() const;

    const std::string& getQName() const { return m_qName; }
    const uint getQType() const { return m_qType; }
    const uint getQClass() const { return m_qClass; }

    void setQName(const std::string& qName) { m_qName = qName; }
    void setQType(uint qType) { m_qType = qType;  }
    void setQClass(uint qClass) { m_qClass = qClass;  }

private:
    std::string m_qName;
    uint m_qType;
    uint m_qClass;

    void decode_qname(const char*& buffer);
    void encode_qname(char*& buffer, const std::string& domain);
};

}


