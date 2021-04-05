#pragma once

#include <stdint.h>
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "stalk_types.h"
#include "stalk_route.h"


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
              const std::string& certificate = "",
              VerifyCallbackFn verifyCallbackFn = VerifyCallbackFn());
    ~WebServer();

    /// Set to use a custom ssl::context, instead of the default.
    WebServer& setSslContext(boost::asio::ssl::context&& ctx);
    boost::asio::ssl::context& sslContext();

    /// Set the handler to be called for not-found or invalid-method requests.
    /// Server will respond with not-found / invalid-method etc status if no handler set.
    WebServer& setRouteErrorHandler(UnroutedRequestCb cb = UnroutedRequestCb());

    /// Set the handler called when a client with a peer certificate is presented.
    WebServer& setVerifyCallbackFn(VerifyCallbackFn verifyCallbackFn);

    void addHttpRoute(Route::Http&& route);
    void removeHttpRoute(const std::string& path);
    void addWebsocketRoute(Route::Websocket&& route);
    void removeWebsocketRoute(const std::string& path);

    void run();
    void stop();
    /// Get the listening port. Will be the actual listening port, eg if provided '0' allowing the OS to choose a port.
    uint16_t port() const;

private:

    std::unique_ptr<WebServerImpl> impl_;
};

} // namespace Stalk
