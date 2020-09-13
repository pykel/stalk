#ifndef stalk_server_INCLUDED
#define stalk_server_INCLUDED

#include <stdint.h>
#include <string>
#include <memory>
#include "stalk_route.h"


namespace boost { namespace asio {
class io_context;
} }


namespace Stalk
{

class WebServerImpl;

// Accepts incoming connections and launches the sessions
class WebServer : public std::enable_shared_from_this<WebServer>
{
public:

    WebServer(boost::asio::io_context& ioc,
           const std::string& address,
           uint16_t port,
           const std::string& privateKey = "",
           const std::string& certificate = "");
    ~WebServer();

    void run();
    void stop();
    uint16_t port() const;

    void addHttpRoute(Route::Http&& route);
    void removeHttpRoute(const std::string& path);
    void addWebsocketRoute(Route::Websocket&& route);
    void removeWebsocketRoute(const std::string& path);

private:

    std::unique_ptr<WebServerImpl> impl_;
};

} // namespace Stalk

#endif

