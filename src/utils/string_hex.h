#pragma once

#include <string>

namespace StringUtils
{

template<typename T>
inline std::string toHexString(const T& begin, const T& end, int delim = -1)
{
    static const char hex_table[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    std::string ret;
    ret.reserve((end - begin) * 2);

    bool haveVal = false;
    auto it = begin;
    while (it != end)
    {
        if (haveVal && delim > 0)
            ret.push_back(delim);

        const auto& d = (*it);
        ret.push_back(hex_table[(d >> 4) & 0xf]);
        ret.push_back(hex_table[d & 0xf]);
        haveVal = true;
        ++it;
    }
    return ret;
}

} // namespace StringUtils
