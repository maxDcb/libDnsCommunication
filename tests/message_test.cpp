#include "message.hpp"
#include <cassert>

using namespace dns;

struct MessageHdrTest : public Message {
    MessageHdrTest() : Message(Message::Response) {}

    int code(char*) override { return 0; }
    void decode(const char*, int) override {}

    using Message::code_hdr;
    using Message::decode_hdr;

    void setRA(uint v) { m_ra = v; }
    uint getRA() const { return m_ra; }
};

int main() {
    char buffer[12] = {};
    char* wptr = buffer;

    MessageHdrTest msg;
    msg.setRA(1);
    msg.code_hdr(wptr);

    const char* rptr = buffer;
    MessageHdrTest result;
    result.decode_hdr(rptr);

    assert(result.getRA() == 1);
    return 0;
}

