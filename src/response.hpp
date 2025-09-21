#pragma once

#include "message.hpp"

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>


namespace dns
{

class Response : public Message
{
public:

    enum Code { Ok=0, FormatError, ServerFailure, NameError, NotImplemented, Refused };

    struct TxtRdata { std::vector<std::string> texts; };
    struct AddressRdata { std::vector<uint8_t> bytes; };
    struct DomainRdata {
        std::string name;
        std::optional<uint16_t> preference;
    };
    struct RawRdata { std::vector<uint8_t> bytes; };
    using RdataVariant = std::variant<std::monostate, TxtRdata, AddressRdata, DomainRdata, RawRdata>;

    Response();
    ~Response();

    int code(char* buffer) override;
    void decode(const char* buffer, int size) override;

    std::string asString() const override;

    void setRCode(Code code) { m_rcode = code; }
    void setName(const std::string& value) { m_name = value; }
    void setType(const uint value) { m_type = value; }
    void setClass(const uint value) { m_class = value; }
    void setTtl(const ulong value) { m_ttl = value; }
    void setRdLength(const uint value) { m_rdLength = value; }

    void clearRdata();
    void setTxtRdata(const std::string& value);
    void setTxtRdata(const TxtRdata& value);
    void setAddressRdata(const std::vector<uint8_t>& value);
    void setAddressRdata(const AddressRdata& value);
    void setDomainRdata(const std::string& value);
    void setDomainRdata(const DomainRdata& value);
    void setRawRdata(const std::vector<uint8_t>& value);
    void setRawRdata(const RawRdata& value);

    const RdataVariant& getRdata() const { return m_rdata; }
    std::string getRdataAsString() const;
    const std::string& getName() const { return m_name; }

private:
    std::string m_name;
    uint m_type;
    uint m_class;
    ulong m_ttl;
    uint m_rdLength;
    RdataVariant m_rdata;

    void decode_domain(const char*& buffer, std::string& domain, const char* begin, const char* end);
    void code_domain(char*& buffer, const std::string& domain) const;

    void encodeAddressRdata(char*& buffer, const AddressRdata& data) const;
    void encodeDomainRdata(char*& buffer, const DomainRdata& data) const;
    void encodeTxtRdata(char*& buffer, const TxtRdata& data) const;
    void encodeRawRdata(char*& buffer, const RawRdata& data) const;

    AddressRdata decodeAddressRdata(const char*& buffer, uint16_t length);
    DomainRdata decodeDomainRdata(const char*& buffer, const char* begin, const char* end, bool hasPreference);
    TxtRdata decodeTxtRdata(const char*& buffer, uint16_t length);
    RawRdata decodeRawRdata(const char*& buffer, uint16_t length);

    void encodeCurrentRdata(char*& buffer) const;
    uint computeRdataLength() const;
    uint computeDomainEncodedLength(const std::string& domain) const;
};

}


