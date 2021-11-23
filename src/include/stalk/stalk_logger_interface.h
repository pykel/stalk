#pragma once

#include <string>
#include <string_view>
#include <functional>

namespace Stalk
{

namespace LoggerInterface
{
    enum Level
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warn = 3,
        Err = 4,
        Critical = 5,
        Off = 6
    };

    using ErrorHandler = std::function<void(const std::string&)>;
    using LogCb = std::function<void(Level,const std::string_view& msg)>;

    void setDefaultLevel(Level level);
    void setLogCb(LogCb cb);

    //static Level levelFromString(const char* lvl);
}

} // namespace Stalk


