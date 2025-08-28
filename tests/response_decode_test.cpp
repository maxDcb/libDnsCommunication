#include <cassert>
#include <string>

#include "response.hpp"

using namespace dns;

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
        0x00,0x04,  // RDLENGTH (length of text only, as expected by decoder)
        0x04,'t','e','s','t' // TXT length and data
    };

    Response resp;
    resp.decode(reinterpret_cast<const char*>(packet), sizeof(packet));
    assert(resp.getName() == "example.com");
    assert(resp.getRdata() == "test");
    return 0;
}
