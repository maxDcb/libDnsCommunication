#pragma once

#include <cctype>
#include <algorithm> 


namespace dns 
{

struct Packet 
{
    std::string data;
    bool isFull;
    std::string id;
};

// https://github.com/iagox86/dnscat2
#define MAX_FIELD_LENGTH 62
#define MAX_DNS_LENGTH   255

/* The max length is:
 * 255 because that's the max DNS length
 * Halved, because we encode in hex
 * Minus the length of the domain, which is appended
 * Minus 1, for the period right before the domain
 * Minus the number of periods that could appear within the name
 */
inline int getMaxMsgLen(const std::string& domain)
{
    return ((255/2) - domain.size() - 1 - ((MAX_DNS_LENGTH / MAX_FIELD_LENGTH) + 1));
}

std::string stringToHex(const std::string& input);
std::string hexToString(const std::string& hex);

std::string addDotEvery62Chars(const std::string& str);

std::string generateRandomString(int length);


bool startsWith(const std::string& str, const std::string& prefix);
bool endsWith(const std::string& fullString, const std::string& ending);

inline std::string str_tolower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); } );
    return s;
}

}