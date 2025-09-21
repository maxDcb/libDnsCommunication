#include <cassert>
#include <string>

#include "response.hpp"

using namespace dns;

namespace {
size_t encodedDomainLength(const std::string& domain) {
    size_t length = 1; // null terminator
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string::npos) {
            end = domain.size();
        }
        length += 1 + (end - start);
        start = end + 1;
    }
    return length;
}
}

int main() {
    const std::string domain = "example.com";

    Response resp;
    resp.setID(0x1234);
    resp.setQdCount(1);
    resp.setAnCount(0);
    resp.setNsCount(0);
    resp.setName(domain);
    resp.setType(16); // TXT
    resp.setClass(1); // IN
    resp.setRCode(Response::NameError);
    resp.setRdLength(0);

    char buffer[512] = {};
    int size = resp.code(buffer);

    const size_t expectedSize = 12 + encodedDomainLength(domain) + 4; // header + question
    assert(size == static_cast<int>(expectedSize));

    Response decoded;
    decoded.decode(buffer, size);

    assert(decoded.getQdCount() == 1);
    assert(decoded.getAnCount() == 0);
    assert(decoded.getNsCount() == 0);
    assert(decoded.getName() == domain);
    assert(decoded.getRdata().empty());

    return 0;
}
