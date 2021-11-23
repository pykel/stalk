#pragma once

#include <iostream>
#include <string>
#include <string_view>
#include <memory>
#include <functional>
#include <atomic>

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ostream.h>

#include "stalk/stalk_logger_interface.h"

namespace Stalk
{

class Logger
{
public:

    using Level = Stalk::LoggerInterface::Level;

    using ErrorHandler = Stalk::LoggerInterface::ErrorHandler;
    using LogCb = Stalk::LoggerInterface::LogCb;

    Logger() {}
    Logger(const std::string& name) : name_(name), level_(defaultLevel_.load()) {}

    static void setDefaultLevel(Level level) { defaultLevel_ = level; }
    static void setLogCb(LogCb cb) { logCb_ = cb; }
    static std::shared_ptr<Logger> get(const std::string& name) { return std::make_shared<Logger>(name); }

    void setLevel(Level level) { level_ = level; }
    int level() const { return level_; }
    static Level levelFromString(const char* lvl);

#define LOG_FUNC(name, level) \
    template<typename FormatString, typename... Args>                   \
    void name(const FormatString &fmt, const Args &... args)            \
    {                                                                   \
        if (!shouldLog(level))                                          \
            return;                                                     \
        log(level, fmt, args...);                                       \
    }                                                                   \
    template<typename MessageString>                                    \
    void name(const MessageString& msg)                                 \
    {                                                                   \
        if (!shouldLog(level))                                          \
            return;                                                     \
        log(level, msg);                                                \
    }

    LOG_FUNC(trace, Level::Trace)
    LOG_FUNC(debug, Level::Debug)
    LOG_FUNC(info, Level::Info)
    LOG_FUNC(warn, Level::Warn)
    LOG_FUNC(error, Level::Err)
    LOG_FUNC(critical, Level::Critical)

private:
    bool shouldLog(Level level) const { return level >= level_; }

    static const char* levelName(Level level)
    {
        static const char* levelNames[] = { "trace", "debug", "info", "warning", "error", "critical", "off" };
        return level > (sizeof(levelNames) / sizeof(const char*)) ? "unknown" : levelNames[level];
    }

    using string_view_t = fmt::basic_string_view<char>;
    using memory_buf_t = fmt::basic_memory_buffer<char, 250>;

    template<typename FormatString, typename... Args>
    inline void log(Level lvl, const FormatString &fmt, const Args &... args)
    {
        try
        {
            memory_buf_t buf;
            fmt::format_to(buf, fmt, args...);

            if (!logCb_)
            {
                const auto view = std::string_view(buf.data(), buf.size());// string_view_t(buf.data(), buf.size());
                std::cout << name_ << ":" << levelName(lvl) << ": " << view << std::endl;
            }
            else
            {
                std::string msg = "[" + name_ + "] " + std::string(buf.data(), buf.size());
                logCb_(lvl, msg);
            }
        }
        catch (const std::exception &e)
        {
            if (errorHandler_)
                errorHandler_(e.what());
        }
        catch (...)
        {
            if (errorHandler_)
                errorHandler_("Unknown exception in logger");
            else
                std::cerr << "Unknown exception in logger" << std::endl;
        }
    }

    void log(Level lvl, const std::string& msg);

    std::string name_;
    std::atomic<int> level_;
    static std::atomic<int> defaultLevel_;
    ErrorHandler errorHandler_;
    static LogCb logCb_;
};

using LogPtr = std::shared_ptr<Logger>;
using Log = std::shared_ptr<Logger>;

} // namespace Stalk
