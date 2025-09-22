#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

    void setName(const std::string& value);
    void setAnswerName(const std::string& value);
    void setType(const uint value);
    void setClass(const uint value);
    void setTtl(const ulong value) { m_ttl = value; }
    void setRdLength(const uint value) { m_rdLength = value; }
    void setRdata(const std::string& value);
    void setRdataBytes(const std::vector<uint8_t>& data);
    void setMxPreference(uint16_t preference) { m_mxPreference = preference; }

    void clearAnswer();

    const std::string& getQuestionName() const { return m_questionName; }
    uint getQuestionType() const { return m_questionType; }
    uint getQuestionClass() const { return m_questionClass; }

    const std::string& getRdata() const { return m_rdata; }
    const std::vector<uint8_t>& getRdataBytes() const { return m_rdataBinary; }
    const std::vector<std::string>& getTxtStrings() const { return m_txtStrings; }
    uint16_t getMxPreference() const { return m_mxPreference; }
    const std::string& getName() const { return m_answerName; }
    uint getType() const { return m_answerType; }
    uint getClass() const { return m_answerClass; }
    
private:
    std::string m_questionName;
    uint m_questionType;
    uint m_questionClass;

    std::string m_answerName;
    uint m_answerType;
    uint m_answerClass;
    ulong m_ttl;
    uint m_rdLength;
    std::string m_rdata;
    std::vector<uint8_t> m_rdataBinary;
    std::vector<std::string> m_txtStrings;
    uint16_t m_mxPreference;

    void decode_domain(const char*& buffer, std::string& domain, const char* begin, const char* end);
    void code_domain(char*& buffer, const std::string& domain);

    void parse_rdata(uint16_t type, const char* data, uint16_t length,
                     const char* begin, const char* end);
    std::vector<uint8_t> build_rdata() const;
    std::vector<uint8_t> encode_domain_rdata(const std::string& domain) const;
    std::vector<uint8_t> encode_txt_rdata(const std::string& text) const;
    std::vector<uint8_t> encode_mx_rdata(uint16_t preference, const std::string& exchange) const;
    std::vector<uint8_t> encode_address_rdata(int family, const std::string& address) const;
    void skip_record(const char*& buffer, const char* begin, const char* end);
};

}


