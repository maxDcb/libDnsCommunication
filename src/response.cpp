#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

#ifdef __linux__

#include <arpa/inet.h>

#elif _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#endif

#include "message.hpp"
#include "response.hpp"

using namespace std;
using namespace dns;

namespace
{

/// Helper to convert two bytes to a 16-bit unsigned integer without advancing the pointer.
static uint16_t peek16(const char* data)
{
    return static_cast<uint16_t>(static_cast<uint8_t>(data[0]) << 8 |
                                 static_cast<uint8_t>(data[1]));
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex)
{
    if (hex.size() % 2 != 0)
        return {};

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);
        if (high < 0 || low < 0)
            return {};
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

static std::string bytes_to_hex(const char* data, size_t length)
{
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

} // namespace

Response::Response()
: Message(Message::Response)
, m_questionType(0)
, m_questionClass(0)
, m_answerType(0)
, m_answerClass(0)
, m_ttl(0)
, m_rdLength(0)
, m_mxPreference(0)
{}

Response::~Response() = default;

void Response::setName(const std::string& value)
{
    m_questionName = value;
    m_answerName = value;
}

void Response::setAnswerName(const std::string& value)
{
    m_answerName = value;
}

void Response::setType(const uint value)
{
    m_questionType = value;
    m_answerType = value;
}

void Response::setClass(const uint value)
{
    m_questionClass = value;
    m_answerClass = value;
}

void Response::setRdata(const std::string& value)
{
    m_rdata = value;
    m_rdataBinary.clear();
    m_txtStrings.clear();
}

void Response::setRdataBytes(const std::vector<uint8_t>& data)
{
    m_rdataBinary = data;
    m_rdata.assign(data.begin(), data.end());
    m_txtStrings.clear();
    m_rdLength = static_cast<uint>(data.size());
}

void Response::clearAnswer()
{
    m_anCount = 0;
    m_answerName.clear();
    m_answerType = 0;
    m_answerClass = 0;
    m_ttl = 0;
    m_rdLength = 0;
    m_rdata.clear();
    m_rdataBinary.clear();
    m_txtStrings.clear();
    m_mxPreference = 0;
}

string Response::asString() const
{
    ostringstream text;
    text << endl << "RESPONSE { ";
    text << Message::asString();

    text << "\tqname: " << m_questionName << endl;
    text << "\tqtype: " << m_questionType << endl;
    text << "\tqclass: " << m_questionClass << endl;

    text << "\tanswerName: " << m_answerName << endl;
    text << "\tanswerType: " << m_answerType << endl;
    text << "\tanswerClass: " << m_answerClass << endl;
    text << "\tttl: " << m_ttl << endl;
    text << "\trdLength: " << m_rdLength << endl;
    text << "\tmxPreference: " << m_mxPreference << endl;
    text << "\trdata (text): " << m_rdata << " }" << dec;

    return text.str();
}

void Response::decode(const char* buffer, int size)
{
    const char* begin = buffer;
    const char* end = buffer + size;

    m_questionName.clear();
    m_answerName.clear();
    m_rdata.clear();
    m_rdataBinary.clear();
    m_txtStrings.clear();
    m_mxPreference = 0;
    m_rdLength = 0;
    m_questionType = 0;
    m_questionClass = 0;
    m_answerType = 0;
    m_answerClass = 0;
    m_ttl = 0;

    resetEdns();

    if (size < static_cast<int>(HDR_OFFSET))
        return;

    decode_hdr(buffer);
    const char* cursor = begin + HDR_OFFSET;

    auto safe_get16 = [&](const char*& ptr) -> uint16_t {
        if (ptr + 2 > end)
        {
            ptr = end;
            return 0;
        }
        return static_cast<uint16_t>(get16bits(ptr));
    };

    auto safe_get32 = [&](const char*& ptr) -> uint32_t {
        if (ptr + 4 > end)
        {
            ptr = end;
            return 0;
        }
        return static_cast<uint32_t>(get32bits(ptr));
    };

    for (uint i = 0; i < m_qdCount && cursor < end; ++i)
    {
        std::string qname;
        decode_domain(cursor, qname, begin, end);
        uint16_t qtype = safe_get16(cursor);
        uint16_t qclass = safe_get16(cursor);
        if (i == 0)
        {
            m_questionName = qname;
            m_questionType = qtype;
            m_questionClass = qclass;
        }
    }

    for (uint i = 0; i < m_anCount && cursor < end; ++i)
    {
        std::string name;
        decode_domain(cursor, name, begin, end);
        uint16_t type = safe_get16(cursor);
        uint16_t klass = safe_get16(cursor);
        uint32_t ttl = safe_get32(cursor);
        uint16_t rdlength = safe_get16(cursor);
        if (cursor + rdlength > end)
        {
            rdlength = static_cast<uint16_t>(std::max<long>(0, end - cursor));
        }

        if (i == 0)
        {
            m_answerName = name;
            m_answerType = type;
            m_answerClass = klass;
            m_ttl = ttl;
            parse_rdata(type, cursor, rdlength, begin, end);
        }

        cursor += rdlength;
    }

    for (uint i = 0; i < m_nsCount && cursor < end; ++i)
    {
        skip_record(cursor, begin, end);
    }

    for (uint i = 0; i < m_arCount && cursor < end; ++i)
    {
        const char* recordStart = cursor;
        if (!decodeEdns(cursor, end))
        {
            cursor = recordStart;
            skip_record(cursor, begin, end);
        }
    }
}

int Response::code(char* buffer)
{
    char* bufferBegin = buffer;

    code_hdr(buffer);
    buffer += HDR_OFFSET;

    if (m_qdCount > 0 && !m_questionName.empty())
    {
        code_domain(buffer, m_questionName);
        put16bits(buffer, m_questionType);
        put16bits(buffer, m_questionClass);
    }

    if (m_anCount > 0)
    {
        const std::string owner = m_answerName.empty() ? m_questionName : m_answerName;
        code_domain(buffer, owner);
        put16bits(buffer, m_answerType);
        put16bits(buffer, m_answerClass);
        put32bits(buffer, m_ttl);

        std::vector<uint8_t> rdata = build_rdata();
        m_rdLength = static_cast<uint>(rdata.size());
        m_rdataBinary = rdata;
        put16bits(buffer, m_rdLength);
        if (!rdata.empty())
        {
            std::memcpy(buffer, rdata.data(), rdata.size());
            buffer += rdata.size();
        }
    }

    if (hasEdns())
    {
        encodeEdns(buffer);
    }

    int size = static_cast<int>(buffer - bufferBegin);
    log_buffer(bufferBegin, size);

    return size;
}

void Response::decode_domain(const char*& buffer, std::string& domain,
                             const char* begin, const char* end)
{
    domain.clear();

    const char* cur = buffer;
    bool jumped = false;
    std::set<const char*> visited;

    while (cur < end)
    {
        uint8_t len = static_cast<uint8_t>(*cur);

        if ((len & 0xC0) == 0xC0)
        {
            if (cur + 1 >= end) { buffer = end; return; }
            uint16_t offset = ((len & 0x3F) << 8) | static_cast<uint8_t>(cur[1]);
            const char* ptr = begin + offset;
            if (ptr < begin || ptr >= end || visited.count(ptr))
            {
                buffer = end;
                return;
            }
            visited.insert(ptr);
            if (!jumped)
            {
                buffer = cur + 2;
                jumped = true;
            }
            cur = ptr;
            continue;
        }

        if (len == 0)
        {
            ++cur;
            if (!jumped) buffer = cur;
            return;
        }

        ++cur;
        if (cur + len > end) { buffer = end; return; }
        domain.append(cur, len);
        cur += len;
        if (*cur != 0) domain.push_back('.');
    }

    buffer = end;
}

void Response::code_domain(char*& buffer, const std::string& domain)
{
    if (domain.empty())
    {
        *buffer++ = 0;
        return;
    }

    int start = 0;
    int end = 0;

    while (start < static_cast<int>(domain.size()))
    {
        end = domain.find('.', start);
        if (end == std::string::npos)
            end = static_cast<int>(domain.size());

        int labelLen = end - start;
        int processed = 0;
        while (processed < labelLen)
        {
            int chunkLen = std::min(63, labelLen - processed);
            *buffer++ = static_cast<char>(chunkLen);
            for (int i = 0; i < chunkLen; ++i)
            {
                *buffer++ = domain[start + processed + i];
            }
            processed += chunkLen;
        }

        start = end + 1;
    }

    *buffer++ = 0;
}

void Response::parse_rdata(uint16_t type, const char* data, uint16_t length,
                           const char* begin, const char* end)
{
    m_rdLength = length;
    m_rdataBinary.assign(data, data + length);
    m_rdata.clear();
    m_txtStrings.clear();

    switch (type)
    {
        case 16: // TXT
        {
            const char* ptr = data;
            uint16_t remaining = length;
            std::string combined;

            while (remaining > 0)
            {
                uint8_t chunkLen = static_cast<uint8_t>(*ptr++);
                --remaining;
                if (chunkLen > remaining)
                    chunkLen = remaining;

                std::string piece(ptr, ptr + chunkLen);
                m_txtStrings.push_back(piece);
                combined.append(piece);
                ptr += chunkLen;
                remaining -= chunkLen;
            }

            if (length == 0)
                m_txtStrings.emplace_back();

            m_rdata = combined;
            break;
        }
        case 5:  // CNAME
        case 2:  // NS
        case 12: // PTR
        {
            const char* ptr = data;
            decode_domain(ptr, m_rdata, begin, end);
            break;
        }
        case 15: // MX
        {
            if (length >= 2)
            {
                m_mxPreference = peek16(data);
                const char* ptr = data + 2;
                decode_domain(ptr, m_rdata, begin, end);
            }
            else
            {
                m_mxPreference = 0;
                m_rdata.clear();
            }
            break;
        }
        case 1: // A
        {
            if (length == 4)
                // Convert IPv4 bytes to hex so the tunneling logic can
                // reassemble the payload without additional parsing.
                m_rdata = bytes_to_hex(data, length);
            break;
        }
        case 28: // AAAA
        {
            if (length == 16)
                // Same strategy for IPv6: expose the raw bytes as hex.
                m_rdata = bytes_to_hex(data, length);
            break;
        }
        default:
        {
            m_rdata.assign(data, data + length);
            break;
        }
    }
}

std::vector<uint8_t> Response::build_rdata() const
{
    if (!m_rdataBinary.empty())
        return m_rdataBinary;

    switch (m_answerType)
    {
        case 16:
            return encode_txt_rdata(m_rdata);
        case 5:
        case 2:
        case 12:
            return encode_domain_rdata(m_rdata);
        case 15:
            return encode_mx_rdata(m_mxPreference, m_rdata);
        case 1:
            return encode_address_rdata(AF_INET, m_rdata);
        case 28:
            return encode_address_rdata(AF_INET6, m_rdata);
        default:
            return std::vector<uint8_t>(m_rdata.begin(), m_rdata.end());
    }
}

std::vector<uint8_t> Response::encode_domain_rdata(const std::string& domain) const
{
    std::vector<uint8_t> out;
    if (domain.empty())
    {
        out.push_back(0);
        return out;
    }

    size_t start = 0;
    while (start < domain.size())
    {
        size_t dot = domain.find('.', start);
        if (dot == std::string::npos)
            dot = domain.size();

        std::string label = domain.substr(start, dot - start);
        size_t consumed = 0;
        while (consumed < label.size())
        {
            size_t chunk = std::min<size_t>(63, label.size() - consumed);
            out.push_back(static_cast<uint8_t>(chunk));
            out.insert(out.end(), label.begin() + consumed, label.begin() + consumed + chunk);
            consumed += chunk;
        }

        start = dot + 1;
    }

    out.push_back(0);
    return out;
}

std::vector<uint8_t> Response::encode_txt_rdata(const std::string& text) const
{
    std::vector<uint8_t> out;
    if (text.empty())
    {
        out.push_back(0);
        return out;
    }

    size_t pos = 0;
    while (pos < text.size())
    {
        size_t chunk = std::min<size_t>(255, text.size() - pos);
        out.push_back(static_cast<uint8_t>(chunk));
        out.insert(out.end(), text.begin() + pos, text.begin() + pos + chunk);
        pos += chunk;
    }

    return out;
}

std::vector<uint8_t> Response::encode_mx_rdata(uint16_t preference, const std::string& exchange) const
{
    std::vector<uint8_t> domain = encode_domain_rdata(exchange);
    std::vector<uint8_t> out;
    out.reserve(domain.size() + 2);
    out.push_back(static_cast<uint8_t>((preference >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(preference & 0xFF));
    out.insert(out.end(), domain.begin(), domain.end());
    return out;
}

std::vector<uint8_t> Response::encode_address_rdata(int family, const std::string& address) const
{
    size_t expected = (family == AF_INET) ? 4 : (family == AF_INET6 ? 16 : 0);
    if (expected == 0)
        return {};

    bool looksHex = !address.empty() &&
                    address.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos &&
                    address.size() == expected * 2;
    if (looksHex)
        return hex_to_bytes(address);

    std::vector<uint8_t> out(expected);
#ifdef _WIN32
    if (InetPtonA(family, address.c_str(), out.data()) != 1)
        return {};
#else
    if (inet_pton(family, address.c_str(), out.data()) != 1)
        return {};
#endif
    return out;
}

void Response::skip_record(const char*& buffer, const char* begin, const char* end)
{
    if (buffer >= end)
        return;

    std::string name;
    decode_domain(buffer, name, begin, end);

    if (buffer + 10 > end)
    {
        buffer = end;
        return;
    }

    buffer += 2; // type
    buffer += 2; // class
    buffer += 4; // ttl

    uint16_t rdlen = peek16(buffer);
    buffer += 2;

    if (buffer + rdlen > end)
        buffer = end;
    else
        buffer += rdlen;
}

