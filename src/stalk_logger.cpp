#include "stalk/stalk_logger.h"

namespace Stalk
{

void Logger::log(Level lvl, const std::string& msg)
{
    try
    {
        const auto view = std::string_view(msg.data(), msg.size());// string_view_t(buf.data(), buf.size());

        if (!logCb_)
        {
            std::cout << name_ << ":" << levelName(Level::Trace) << ": " << view << std::endl;
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

std::atomic<int> Logger::defaultLevel_ = Logger::Level::Info;
Logger::LogCb Logger::logCb_ = Logger::LogCb();

} // namespace Stalk

