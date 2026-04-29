#include "message.hpp"
#include "dnsPacker.hpp"
#include <cassert>
#include <string>

using namespace dns;

struct MessageTest : public Message {
    MessageTest() : Message(Message::Query) {}
    int code(char*) override { return 0; }
    void decode(const char*, int) override {}
    void put32(char*& buffer, ulong value) { put32bits(buffer, value); }
};

int main() {
    char buf[4];
    char* ptr = buf;
    MessageTest mt;
    mt.put32(ptr, 0x12345678);
    assert(buf[0] == 0x12);
    assert(buf[1] == 0x34);
    assert(buf[2] == 0x56);
    assert(buf[3] == 0x78);

    std::string a = generateRandomString(8);
    std::string b = generateRandomString(8);
    assert(a.size() == 8);
    assert(b.size() == 8);
    assert(a != b);

    const std::string binaryData("\0\x01\x05\x0A\x10\x1F\x7F\x80\xFF", 9);
    std::string hex = stringToHex(binaryData);
    assert(hex.size() == binaryData.size() * 2);
    std::string roundTrip = hexToString(hex);
    assert(roundTrip == binaryData);
    return 0;
}
