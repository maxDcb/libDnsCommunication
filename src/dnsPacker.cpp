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
    std::string result = "";
    for (char c : input) 
    {
        int ascii = static_cast<int>(c);
        std::stringstream ss;
        ss << std::hex << std::uppercase << ascii;
        result += ss.str();
    }
    return result;
}


std::string hexToString(const std::string& hex) 
{
    int len = hex.length();
    std::string result;
    for(int i=0; i< len; i+=2)
    {
        std::string byte = hex.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        result.push_back(chr);
    }
    return result;
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

    return result;
}


std::string generateRandomString(int length) 
{
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static std::mt19937 rng{std::random_device{}()};
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