#pragma once
#include <string>
#include <map>
#include <sstream>
#include <algorithm>

namespace nlohmann {
class json {
public:
    using object_t = std::map<std::string, std::string>;
    json() = default;

    std::string& operator[](const std::string& key) { return data[key]; }
    const std::string& operator[](const std::string& key) const { return data.at(key); }

    std::string dump() const {
        std::ostringstream oss;
        oss << "{";
        bool first = true;
        for(const auto& kv : data) {
            if(!first) oss << ",";
            first = false;
            oss << "\"" << kv.first << "\":";
            if(std::all_of(kv.second.begin(), kv.second.end(), ::isdigit))
                oss << kv.second;
            else
                oss << "\"" << kv.second << "\"";
        }
        oss << "}";
        return oss.str();
    }

    static json parse(const std::string&) { return json(); }

private:
    object_t data;
};
}
