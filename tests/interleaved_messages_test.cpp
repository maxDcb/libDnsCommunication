#include <cassert>
#include <string>
#include <vector>

#include "dns.hpp"
#include "dnsPacker.hpp"

using namespace dns;

class DnsEx : public Dns {
public:
    using Dns::Dns;
    bool hasMessage() const { return !m_msgQueue.empty(); }
    std::string popMessage() { auto m = m_msgQueue.front(); m_msgQueue.pop(); return m; }
    void handle(const std::string& r) { handleResponse(r); }
};

int main() {
    const std::string domain = "example.com";
    // Messages large enough to require fragmentation
    std::string msg1(200, 'A');
    std::string msg2(200, 'B');

    DnsEx sender1(domain);
    DnsEx sender2(domain);
    DnsEx receiver(domain);

    sender1.setMsg(msg1);
    sender2.setMsg(msg2);

    std::vector<std::string> frags1;
    while(sender1.hasMessage()) frags1.push_back(sender1.popMessage());
    std::vector<std::string> frags2;
    while(sender2.hasMessage()) frags2.push_back(sender2.popMessage());

    size_t maxFrag = std::max(frags1.size(), frags2.size());
    for(size_t i = 0; i < maxFrag; ++i) {
        if(i < frags1.size()) receiver.handle(frags1[i]);
        if(i < frags2.size()) receiver.handle(frags2[i]);
    }

    std::string out1 = receiver.getMsg();
    std::string out2 = receiver.getMsg();

    bool ok = ( (out1 == msg1 && out2 == msg2) || (out1 == msg2 && out2 == msg1) );
    if(!ok) return 1;
    return 0;
}
