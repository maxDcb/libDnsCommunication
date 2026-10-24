#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <random>

#include "dnsPacker.hpp"

namespace dns
{


std::string stringToHex(const std::string& input)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (unsigned char c : input)
    {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}


std::string hexToString(const std::string& hex) 
{
    std::string result;
    if (!tryHexToString(hex, result))
        return {};
    return result;
}


bool tryHexToString(const std::string& hex, std::string& output)
{
    output.clear();
    if (hex.empty() || (hex.size() % 2) != 0)
        return false;

    auto hexValue = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return 10 + value - 'a';
        if (value >= 'A' && value <= 'F') return 10 + value - 'A';
        return -1;
    };

    output.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int high = hexValue(hex[i]);
        const int low = hexValue(hex[i + 1]);
        if (high < 0 || low < 0)
        {
            output.clear();
            return false;
        }
        output.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}


std::string addDotEvery62Chars(const std::string& str)
{
    std::string result;
    int count = 0;

    for (char ch : str)
    {
        result.push_back(ch);
        count++;
        if (count == 62)
        {
            result.push_back('.');
            count = 0;
        }
    }

    if (!result.empty() && result.back() == '.')
    {
        result.pop_back();
    }

    return result;
}


std::string generateRandomString(int length) 
{
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(0, charset.size() - 1);
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i)
    {
        result += charset[dist(rng)];
    }
    return result;
}


std::string generateRandomLowcaseString(int length) 
{
    const std::string charset = "0123456789abcdefghijklmnopqrstuvwxyz";
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(0, charset.size() - 1);
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i)
    {
        result += charset[dist(rng)];
    }
    return result;
}


bool startsWith(const std::string& str, const std::string& prefix) 
{
    if (str.length() < prefix.length()) 
    {
        return false;
    }
    for (size_t i = 0; i < prefix.length(); ++i) 
    {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}


bool endsWith(const std::string& fullString, const std::string& ending) 
{ 
    if (ending.size() > fullString.size()) 
        return false; 

    std::string fullStringLow = str_tolower(fullString);
    std::string endingLow = str_tolower(ending);
  
    return fullStringLow.compare(fullStringLow.size() 
                                  - endingLow.size(), 
                              endingLow.size(), endingLow) == 0; 
} 


}
