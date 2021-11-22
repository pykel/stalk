#include "stalk/stalk_logger.h"

namespace Stalk
{

void Logger::log(Level lvl, const std::string& msg)
{
    try
    {
        const auto view = std::string_view(msg.data(), msg.size());

        if (!logCb_)
        {
            std::cout << name_ << ":" << levelName(lvl) << ": " << view << std::endl;
        }
        else
        {
            logCb_(lvl, view);
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

Logger::Level Logger::levelFromString(const char* lvl)
{
    if (strcmp(lvl, "trace") == 0)
        return Level::Trace;
    if (strcmp(lvl, "debug") == 0)
        return Level::Debug;
    if (strcmp(lvl, "info") == 0)
        return Level::Info;
    if (strcmp(lvl, "warning") == 0)
        return Level::Warn;
    if (strcmp(lvl, "error") == 0)
        return Level::Err;
    if (strcmp(lvl, "critical") == 0)
        return Level::Critical;
    if (strcmp(lvl, "off") == 0)
        return Level::Off;

    return Level::Warn;
}

std::atomic<int> Logger::defaultLevel_ = Logger::Level::Info;
Logger::LogCb Logger::logCb_ = Logger::LogCb();

} // namespace Stalk

