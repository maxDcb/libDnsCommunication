#include <algorithm>
#include <iomanip>
#include <sstream>
#include <utility>
#include <set>

#ifdef __linux__

#include <arpa/inet.h>

#elif _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#endif

#include "message.hpp"
#include "response.hpp"

namespace {

template <typename... Ts>
struct Overloaded : Ts...
{
    using Ts::operator()...;
};

template <typename... Ts>
Overloaded(Ts...) -> Overloaded<Ts...>;

}

using namespace std;
using namespace dns;


Response::Response()
: Message(Message::Response)
{
    m_name="";
    m_type=0;
    m_class=0;
    m_ttl=0;
    m_rdLength=0;
    m_rdata = std::monostate{};
}


Response::~Response() = default;


void Response::clearRdata()
{
    m_rdata = std::monostate{};
    m_rdLength = 0;
}


void Response::setTxtRdata(const std::string& value)
{
    TxtRdata data;
    if (value.empty())
    {
        data.texts.emplace_back("");
    }
    else
    {
        size_t pos = 0;
        while (pos < value.size())
        {
            size_t len = std::min<size_t>(255, value.size() - pos);
            data.texts.emplace_back(value.substr(pos, len));
            pos += len;
        }
    }

    setTxtRdata(data);
}


void Response::setTxtRdata(const TxtRdata& value)
{
    TxtRdata normalized;
    if (value.texts.empty())
    {
        normalized.texts.emplace_back("");
    }
    else
    {
        for (const auto& chunk : value.texts)
        {
            if (chunk.empty())
            {
                normalized.texts.emplace_back("");
                continue;
            }

            size_t pos = 0;
            while (pos < chunk.size())
            {
                size_t len = std::min<size_t>(255, chunk.size() - pos);
                normalized.texts.emplace_back(chunk.substr(pos, len));
                pos += len;
            }
        }
    }

    m_rdata = std::move(normalized);
    m_rdLength = computeRdataLength();
}


void Response::setAddressRdata(const std::vector<uint8_t>& value)
{
    setAddressRdata(AddressRdata{value});
}


void Response::setAddressRdata(const AddressRdata& value)
{
    m_rdata = value;
    m_rdLength = computeRdataLength();
}


void Response::setDomainRdata(const std::string& value)
{
    setDomainRdata(DomainRdata{value, std::nullopt});
}


void Response::setDomainRdata(const DomainRdata& value)
{
    m_rdata = value;
    m_rdLength = computeRdataLength();
}


void Response::setRawRdata(const std::vector<uint8_t>& value)
{
    setRawRdata(RawRdata{value});
}


void Response::setRawRdata(const RawRdata& value)
{
    m_rdata = value;
    m_rdLength = computeRdataLength();
}


string Response::getRdataAsString() const
{
    return std::visit(Overloaded{
        [](const std::monostate&) -> string { return {}; },
        [](const TxtRdata& data) -> string {
            string result;
            for (size_t i = 0; i < data.texts.size(); ++i)
            {
                if (i != 0)
                    result.push_back(' ');
                result += data.texts[i];
            }
            return result;
        },
        [](const AddressRdata& data) -> string {
            if (data.bytes.empty())
                return {};

            if (data.bytes.size() == 4)
            {
                ostringstream oss;
                oss << static_cast<int>(data.bytes[0]) << '.'
                    << static_cast<int>(data.bytes[1]) << '.'
                    << static_cast<int>(data.bytes[2]) << '.'
                    << static_cast<int>(data.bytes[3]);
                return oss.str();
            }

            ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (size_t i = 0; i < data.bytes.size(); ++i)
            {
                if (i != 0 && i % 2 == 0)
                    oss << ':';
                oss << std::setw(2) << static_cast<int>(data.bytes[i]);
            }
            return oss.str();
        },
        [](const DomainRdata& data) -> string {
            if (data.preference.has_value())
            {
                ostringstream oss;
                oss << data.preference.value() << ' ' << data.name;
                return oss.str();
            }
            return data.name;
        },
        [](const RawRdata& data) -> string {
            return string(data.bytes.begin(), data.bytes.end());
        }
    }, m_rdata);
}


string Response::asString() const
{
    ostringstream text;
    text << endl << "RESPONSE { ";
    text << Message::asString();

    text << "\tname: " << m_name << endl;
    text << "\ttype: " << m_type << endl;
    text << "\tclass: " << m_class << endl;
    text << "\tttl: " << m_ttl << endl;
    text << "\trdLength: " << m_rdLength << endl;
    text << "\trdata: " << getRdataAsString() << " }" << dec;

    return text.str();
}


void Response::decode(const char* buffer, int size)
{
    const char* begin = buffer;
    const char* end = buffer + size;

    clearRdata();

    decode_hdr(buffer);
    buffer += HDR_OFFSET;

    if (m_qdCount > 0)
    {
        std::string questionName;
        decode_domain(buffer, questionName, begin, end);
        m_name = questionName;
        m_type = get16bits(buffer);
        m_class = get16bits(buffer);
    }

    if (m_anCount == 0)
    {
        return;
    }

    std::string answerName;
    decode_domain(buffer, answerName, begin, end);
    m_name = answerName;
    m_type = get16bits(buffer);
    m_class = get16bits(buffer);
    m_ttl = get32bits(buffer);
    m_rdLength = get16bits(buffer);

    if (buffer + m_rdLength > end)
    {
        buffer = end;
        clearRdata();
        return;
    }

    switch (m_type)
    {
        case 1:
        case 28:
            m_rdata = decodeAddressRdata(buffer, static_cast<uint16_t>(m_rdLength));
            break;
        case 5:
            m_rdata = decodeDomainRdata(buffer, begin, end, false);
            break;
        case 15:
        {
            if (m_rdLength < 2)
            {
                m_rdata = decodeRawRdata(buffer, static_cast<uint16_t>(m_rdLength));
                break;
            }
            DomainRdata domain = decodeDomainRdata(buffer, begin, end, true);
            m_rdata = std::move(domain);
            break;
        }
        case 16:
            m_rdata = decodeTxtRdata(buffer, static_cast<uint16_t>(m_rdLength));
            break;
        default:
            m_rdata = decodeRawRdata(buffer, static_cast<uint16_t>(m_rdLength));
            break;
    }
}


int Response::code(char* buffer)
{
    char* bufferBegin = buffer;

    code_hdr(buffer);
    buffer += HDR_OFFSET;

    if (m_qdCount > 0)
    {
        code_domain(buffer, m_name);
        put16bits(buffer, m_type);
        put16bits(buffer, m_class);
    }

    if (m_anCount > 0)
    {
        put16bits(buffer, 0xC00C);
        put16bits(buffer, m_type);
        put16bits(buffer, m_class);
        put32bits(buffer, m_ttl);

        m_rdLength = computeRdataLength();
        put16bits(buffer, m_rdLength);
        encodeCurrentRdata(buffer);
    }

    int size = buffer - bufferBegin;
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

    while (cur < end) {
        uint8_t len = static_cast<uint8_t>(*cur);

        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= end) { buffer = end; return; }
            uint16_t offset = ((len & 0x3F) << 8) | static_cast<uint8_t>(cur[1]);
            const char* ptr = begin + offset;
            if (ptr < begin || ptr >= end || visited.count(ptr)) {
                buffer = end;
                return;
            }
            visited.insert(ptr);
            if (!jumped) {
                buffer = cur + 2;
                jumped = true;
            }
            cur = ptr;
            continue;
        }

        if (len == 0) {
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


void Response::code_domain(char*& buffer, const std::string& domain) const
{
    int start(0), end;

    while ((end = domain.find('.', start)) != string::npos)
    {
        *buffer++ = end - start;
        for (int i=start; i<end; i++) {
            *buffer++ = domain[i];
        }
        start = end + 1;
    }

    *buffer++ = domain.size() - start;
    for (int i=start; i<domain.size(); i++) {
        *buffer++ = domain[i];
    }

    *buffer++ = 0;
}


void Response::encodeAddressRdata(char*& buffer, const AddressRdata& data) const
{
    for (auto byte : data.bytes)
    {
        *buffer++ = static_cast<char>(byte);
    }
}


void Response::encodeDomainRdata(char*& buffer, const DomainRdata& data) const
{
    if (data.preference.has_value())
    {
        put16bits(buffer, data.preference.value());
    }

    code_domain(buffer, data.name);
}


void Response::encodeTxtRdata(char*& buffer, const TxtRdata& data) const
{
    for (const auto& text : data.texts)
    {
        *buffer++ = static_cast<char>(text.size());
        std::copy(text.begin(), text.end(), buffer);
        buffer += text.size();
    }
}


void Response::encodeRawRdata(char*& buffer, const RawRdata& data) const
{
    for (auto byte : data.bytes)
    {
        *buffer++ = static_cast<char>(byte);
    }
}


Response::AddressRdata Response::decodeAddressRdata(const char*& buffer, uint16_t length)
{
    AddressRdata data;
    data.bytes.reserve(length);
    for (uint16_t i = 0; i < length; ++i)
    {
        data.bytes.push_back(static_cast<uint8_t>(*buffer++));
    }
    return data;
}


Response::DomainRdata Response::decodeDomainRdata(const char*& buffer, const char* begin,
                                                  const char* end, bool hasPreference)
{
    DomainRdata data;
    if (hasPreference)
    {
        data.preference = static_cast<uint16_t>(get16bits(buffer));
    }
    decode_domain(buffer, data.name, begin, end);
    return data;
}


Response::TxtRdata Response::decodeTxtRdata(const char*& buffer, uint16_t length)
{
    TxtRdata data;
    const char* end = buffer + length;

    while (buffer < end)
    {
        uint8_t chunkLength = static_cast<uint8_t>(*buffer++);
        if (buffer + chunkLength > end)
        {
            chunkLength = static_cast<uint8_t>(end - buffer);
        }
        data.texts.emplace_back(buffer, buffer + chunkLength);
        buffer += chunkLength;
    }

    if (data.texts.empty())
        data.texts.emplace_back("");

    return data;
}


Response::RawRdata Response::decodeRawRdata(const char*& buffer, uint16_t length)
{
    RawRdata data;
    data.bytes.reserve(length);
    for (uint16_t i = 0; i < length; ++i)
    {
        data.bytes.push_back(static_cast<uint8_t>(*buffer++));
    }
    return data;
}


void Response::encodeCurrentRdata(char*& buffer) const
{
    std::visit(Overloaded{
        [](const std::monostate&) {},
        [this, &buffer](const TxtRdata& data) { encodeTxtRdata(buffer, data); },
        [this, &buffer](const AddressRdata& data) { encodeAddressRdata(buffer, data); },
        [this, &buffer](const DomainRdata& data) { encodeDomainRdata(buffer, data); },
        [this, &buffer](const RawRdata& data) { encodeRawRdata(buffer, data); }
    }, m_rdata);
}


uint Response::computeRdataLength() const
{
    return std::visit(Overloaded{
        [](const std::monostate&) -> uint { return 0; },
        [](const TxtRdata& data) -> uint {
            uint total = 0;
            for (const auto& text : data.texts)
                total += static_cast<uint>(1 + text.size());
            return total;
        },
        [](const AddressRdata& data) -> uint {
            return static_cast<uint>(data.bytes.size());
        },
        [this](const DomainRdata& data) -> uint {
            uint length = computeDomainEncodedLength(data.name);
            if (data.preference.has_value())
                length += 2;
            return length;
        },
        [](const RawRdata& data) -> uint {
            return static_cast<uint>(data.bytes.size());
        }
    }, m_rdata);
}


uint Response::computeDomainEncodedLength(const std::string& domain) const
{
    if (domain.empty())
        return 1;

    return static_cast<uint>(domain.size() + 2);
}

