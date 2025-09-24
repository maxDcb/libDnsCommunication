#pragma once

#include <cstdint>
#include <string>

#include "message.hpp"


namespace dns 
{

class Query : public Message
{
public:

    static constexpr uint16_t kDefaultEdnsUdpPayloadSize = 4096;

    Query();
    ~Query();

    std::string encode() const;
    int code(char* buffer);

    void decode(const char* buffer, int size);

    std::string asString() const;

    const std::string& getQName() const { return m_qName; }
    const uint getQType() const { return m_qType; }
    const uint getQClass() const { return m_qClass; }

    void setQName(const std::string& qName) { m_qName = qName; }
    void setQType(uint qType) { m_qType = qType;  }
    void setQClass(uint qClass) { m_qClass = qClass;  }

    void enableEdns0(uint16_t udpPayloadSize = kDefaultEdnsUdpPayloadSize);
    void disableEdns0();
    bool isEdns0Enabled() const { return m_useEdns0; }
    uint16_t getEdnsUdpPayloadSize() const { return m_ednsUdpPayloadSize; }

private:
    std::string m_qName;
    uint m_qType;
    uint m_qClass;

    bool m_useEdns0;
    uint16_t m_ednsUdpPayloadSize;
    uint8_t m_ednsExtendedRcode;
    uint8_t m_ednsVersion;
    uint16_t m_ednsFlags;

    void decode_qname(const char*& buffer);
    void encode_qname(char*& buffer, const std::string& domain);
};

}


