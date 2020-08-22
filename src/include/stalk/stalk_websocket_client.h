#ifndef stalk_websocket_client_INCLUDED
#define stalk_websocket_client_INCLUDED

#include <stdint.h>
#include <string>
#include <memory>
#include <functional>
#include "stalk_request.h"
#include "stalk_response.h"
#include "stalk_connection_detail.h"


namespace boost {

    namespace system {
        class error_code;
    }

    namespace asio {
        class io_context;

        namespace ssl {
            class context;
        }   // boost::asio::ssl

    } // asio
} // boost


namespace Stalk
{

class WebsocketClientImpl;

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient>
{
public:

    /// Websocket Connection Callback
    typedef std::function<void(const boost::system::error_code&, const Response&)> ConnectCb;
    typedef std::function<void(std::string&&)> ReceiveMsgCb;
    typedef std::function<void(const boost::system::error_code&, std::string&&)> ErrorCb;

    WebsocketClient(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx);
    ~WebsocketClient();

    WebsocketClient& key(const std::string& key);
    WebsocketClient& cert(const std::string& cert);

    void connect(bool secureSocket, const std::string& host, const std::string& port, Request&& req, ConnectCb&& connectCb, ReceiveMsgCb&& receiveMsgCb, ErrorCb&& errorCb);
    bool send(const std::string& msg);

    /// Get the HTTP response received when performing Websocket negotiation.
    const Response& connectResponse() const;

    const ConnectionDetail& peerConnectionDetail() const;

    bool stop();

    boost::asio::ssl::context& ctx();

private:

    std::shared_ptr<WebsocketClientImpl> impl_;
};

} // namespace Stalk

#endif
