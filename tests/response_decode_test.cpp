#include <cassert>

#include "response.hpp"

using namespace dns;

int main() {
    // TXT record carrying "test"
    const unsigned char txtPacket[] = {
        0x00,0x01,  // ID
        0x81,0x80,  // Flags
        0x00,0x01,  // QDCOUNT
        0x00,0x01,  // ANCOUNT
        0x00,0x00,  // NSCOUNT
        0x00,0x00,  // ARCOUNT
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x10,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x10,
        0x00,0x01,
        0x00,0x00,0x00,0x3C,
        0x00,0x05,
        0x04,'t','e','s','t'
    };

    Response respTxt;
    respTxt.decode(reinterpret_cast<const char*>(txtPacket), sizeof(txtPacket));
    assert(respTxt.getName() == "example.com");
    assert(respTxt.getRdata() == "test");

    // CNAME record mapping alias.example.com -> payload.example.com
    const unsigned char cnamePacket[] = {
        0x12,0x34,
        0x81,0x80,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,
        0x00,0x00,
        0x05,'a','l','i','a','s',
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x05,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x05,
        0x00,0x01,
        0x00,0x00,0x00,0x3C,
        0x00,0x15,
        0x07,'p','a','y','l','o','a','d',
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00
    };

    Response respCname;
    respCname.decode(reinterpret_cast<const char*>(cnamePacket), sizeof(cnamePacket));
    assert(respCname.getName() == "alias.example.com");
    assert(respCname.getRdata() == "payload.example.com");

    // MX record with preference 10 and exchange payload.example.com
    const unsigned char mxPacket[] = {
        0x20,0x20,
        0x81,0x80,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,
        0x00,0x00,
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x0F,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x0F,
        0x00,0x01,
        0x00,0x00,0x00,0x0A,
        0x00,0x17,
        0x00,0x0A,
        0x07,'p','a','y','l','o','a','d',
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00
    };

    Response respMx;
    respMx.decode(reinterpret_cast<const char*>(mxPacket), sizeof(mxPacket));
    assert(respMx.getName() == "example.com");
    assert(respMx.getMxPreference() == 10);
    assert(respMx.getRdata() == "payload.example.com");

    // A record with address 192.0.2.1 (hex C0000201)
    const unsigned char aPacket[] = {
        0x33,0x33,
        0x81,0x80,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,
        0x00,0x00,
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x01,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,0x00,0x78,
        0x00,0x04,
        0xC0,0x00,0x02,0x01
    };

    Response respA;
    respA.decode(reinterpret_cast<const char*>(aPacket), sizeof(aPacket));
    assert(respA.getRdata() == "C0000201");

    // AAAA record with address 2001:db8::1 (hex 20010DB8000000000000000000000001)
    const unsigned char aaaaPacket[] = {
        0x44,0x44,
        0x81,0x80,
        0x00,0x01,
        0x00,0x01,
        0x00,0x00,
        0x00,0x00,
        0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m',0x00,
        0x00,0x1C,
        0x00,0x01,
        0xC0,0x0C,
        0x00,0x1C,
        0x00,0x01,
        0x00,0x00,0x00,0x01,
        0x00,0x10,
        0x20,0x01,0x0D,0xB8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };

    Response respAaaa;
    respAaaa.decode(reinterpret_cast<const char*>(aaaaPacket), sizeof(aaaaPacket));
    assert(respAaaa.getRdata() == "20010DB8000000000000000000000001");

    return 0;
}
