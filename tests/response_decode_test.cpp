#include <algorithm>
#include <cassert>
#include <cstring>
#include <string>

#include "response.hpp"

using namespace dns;

static unsigned int calcTxtRdLength(const std::string& data)
{
    if (data.empty())
        return 0;

    unsigned int length = 0;
    for (size_t offset = 0; offset < data.size();)
    {
        size_t chunk = std::min<size_t>(255, data.size() - offset);
        length += static_cast<unsigned int>(chunk + 1);
        offset += chunk;
    }

    return length;
}

int main() {
    // Compressed DNS response for TXT record of example.com with "test" as data
    const unsigned char packet[] = {
        0x00,0x00,  // ID
        0x81,0x80,  // Flags
        0x00,0x01,  // QDCOUNT
        0x00,0x01,  // ANCOUNT
        0x00,0x00,  // NSCOUNT
        0x00,0x00,  // ARCOUNT
        // Question section: example.com
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x10,  // QTYPE=TXT
        0x00,0x01,  // QCLASS=IN
        // Answer section: name pointer to offset 12 (0xC00C)
        0xC0,0x0C,
        0x00,0x10,  // TYPE=TXT
        0x00,0x01,  // CLASS=IN
        0x00,0x00,0x00,0x00,  // TTL
        0x00,0x05,  // RDLENGTH (length octet + text)
        0x04,'t','e','s','t' // TXT length and data
    };

    Response resp;
    resp.decode(reinterpret_cast<const char*>(packet), sizeof(packet));
    assert(resp.getName() == "example.com");
    assert(resp.getRdata() == "test");

    Response encodeResp;
    encodeResp.setID(0);
    encodeResp.setQdCount(1);
    encodeResp.setAnCount(1);
    encodeResp.setName("example.com");
    encodeResp.setType(16);
    encodeResp.setClass(1);
    encodeResp.setTtl(0);
    encodeResp.setRCode(Response::Ok);
    std::string payload = "test";
    encodeResp.setRdata(payload);
    encodeResp.setRdLength(calcTxtRdLength(payload));

    char buffer[256] = {0};
    int encodedSize = encodeResp.code(buffer);
    assert(static_cast<size_t>(encodedSize) == sizeof(packet));
    assert(std::memcmp(buffer, packet, sizeof(packet)) == 0);

    const unsigned char packetMulti[] = {
        0x00,0x02,
        0x81,0x80,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,
        0x00,0x00,
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x10,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x10,
        0x00,0x01,
        0x00,0x00,0x00,0x00,
        0x00,0x08,
        0x03,'f','o','o',
        0x03,'b','a','r'
    };

    Response multiResp;
    multiResp.decode(reinterpret_cast<const char*>(packetMulti), sizeof(packetMulti));
    assert(multiResp.getRdata() == "foobar");

    std::string longPayload(300, 'A');
    Response roundTrip;
    roundTrip.setID(0x1234);
    roundTrip.setQdCount(1);
    roundTrip.setAnCount(1);
    roundTrip.setName("example.com");
    roundTrip.setType(16);
    roundTrip.setClass(1);
    roundTrip.setTtl(0);
    roundTrip.setRCode(Response::Ok);
    roundTrip.setRdata(longPayload);
    roundTrip.setRdLength(calcTxtRdLength(longPayload));

    char roundTripBuffer[1024] = {0};
    int roundTripSize = roundTrip.code(roundTripBuffer);

    Response decodedRoundTrip;
    decodedRoundTrip.decode(roundTripBuffer, roundTripSize);
    assert(decodedRoundTrip.getRdata() == longPayload);

    return 0;
}
