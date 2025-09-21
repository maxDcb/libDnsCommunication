#include <cassert>
#include <string>
#include <variant>
#include <vector>

#include "response.hpp"

using namespace dns;

namespace
{

void testTxtDecode()
{
    const unsigned char packet[] = {
        0x00,0x00,
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
        0x00,0x05,
        0x04,'t','e','s','t'
    };

    Response resp;
    resp.decode(reinterpret_cast<const char*>(packet), sizeof(packet));

    assert(resp.getName() == "example.com");
    const auto& rdata = resp.getRdata();
    assert(std::holds_alternative<Response::TxtRdata>(rdata));
    const auto& txt = std::get<Response::TxtRdata>(rdata);
    assert(txt.texts.size() == 1);
    assert(txt.texts[0] == "test");
    assert(resp.getRdataAsString() == "test");
}


void testAEncodeDecode()
{
    Response resp;
    resp.setID(0);
    resp.setQdCount(1);
    resp.setAnCount(1);
    resp.setName("example.com");
    resp.setType(1);
    resp.setClass(1);
    resp.setTtl(300);
    resp.setAddressRdata(std::vector<uint8_t>{192, 0, 2, 1});

    char buffer[512] = {};
    int size = resp.code(buffer);

    Response decoded;
    decoded.decode(buffer, size);

    assert(decoded.getName() == "example.com");
    const auto& rdata = decoded.getRdata();
    assert(std::holds_alternative<Response::AddressRdata>(rdata));
    auto bytes = std::get<Response::AddressRdata>(rdata).bytes;
    assert(bytes == std::vector<uint8_t>({192, 0, 2, 1}));
    assert(decoded.getRdataAsString() == "192.0.2.1");
}

}


int main()
{
    testTxtDecode();
    testAEncodeDecode();
    return 0;
}
