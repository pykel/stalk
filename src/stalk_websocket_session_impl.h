#pragma once

#include <string>
#include <deque>
#include <memory>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl.hpp>
#include "stalk_types_internal.h"
#include "stalk_logger.h"


namespace Stalk
{

class WebsocketSessionImpl
{
public:

    // Construct the session
    WebsocketSessionImpl(uint64_t id);
    virtual ~WebsocketSessionImpl();

    uint64_t id() const;

    // Start the asynchronous operations
    void run(Request&& req);

    // Stop & disconnect
    virtual void stop() = 0;

    virtual bool send(const std::string& msg) = 0;

    WebsocketSessionImpl& setConnectCb(WebsocketConnectCb cb);
    WebsocketSessionImpl& setReadCb(WebsocketReadCb cb);

    const ConnectionDetail& connectionDetail() const;

    const Request& request() const;
    Request& request();

    virtual void do_stop() = 0;
    virtual void do_accept(Request&& req) = 0;

    void on_accept(boost::system::error_code ec);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

protected:

    virtual std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const = 0;
    virtual std::shared_ptr<WebsocketSessionImpl> sharedFromThis() = 0;
    virtual void do_read() = 0;
    virtual void do_write() = 0;
    virtual bool is_open() const = 0;
    void on_send(std::shared_ptr<const std::string> msg);
    void on_write(const boost::system::error_code& ec, std::size_t bytes_transferred);

    void connectCb(bool connected);
    void readCb(std::string&& msg);

    uint64_t id_;
    WebsocketConnectCb connectCb_;
    WebsocketReadCb readCb_;
    LogPtr logger_;
    Request acceptedRequest_;
    bool close_ = false;

    boost::beast::multi_buffer rxBuffer_;
    std::deque<std::shared_ptr<const std::string>> sendQueue_;
    ConnectionDetail connectionDetail_;
};


// Handles a plain WebSocket connection
class PlainWebsocketSession : public WebsocketSessionImpl, public std::enable_shared_from_this<PlainWebsocketSession>
{
public:
    // Create the session
    PlainWebsocketSession(uint64_t id, boost::beast::tcp_stream&& stream, const ConnectionDetail& connectionDetails);

    void stop() override;
    bool send(const std::string& msg) override;
    void do_stop() override;
    void on_close(boost::system::error_code ec);

    boost::beast::websocket::stream<boost::beast::tcp_stream>& stream() { return ws_; }
    const boost::beast::websocket::stream<boost::beast::tcp_stream>& stream() const { return ws_; }

protected:
    std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<WebsocketSessionImpl> sharedFromThis() override { return shared_from_this(); }

    bool is_open() const override;
    void do_accept(Request&& req) override;
    void do_read() override;
    void do_write() override;

private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws_;
};


// Handles an SSL WebSocket connection
class SslWebsocketSession : public WebsocketSessionImpl, public std::enable_shared_from_this<SslWebsocketSession>
{
public:
    // Create the http_session
    SslWebsocketSession(uint64_t id, boost::beast::ssl_stream<boost::beast::tcp_stream>&& stream, const ConnectionDetail& connectionDetails);

    void stop() override;
    bool send(const std::string& msg) override;
    void do_eof();
    void on_shutdown(boost::system::error_code ec);

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& stream() { return ws_; }
    const boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& stream() const { return ws_; }

protected:
    std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<WebsocketSessionImpl> sharedFromThis() override { return shared_from_this(); }

    void do_stop() override;
    bool is_open() const override;
    // Start the asynchronous operation
    void do_accept(Request&& req) override;
    void do_read() override;
    void do_write() override;

private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> ws_;
    bool eof_ = false;
};

std::shared_ptr<PlainWebsocketSession> make_websocket_session(uint64_t id, boost::beast::tcp_stream&& stream, Request&& req,
                                                              WebsocketConnectCb connectCb = WebsocketConnectCb(),
                                                              WebsocketReadCb readCb = WebsocketReadCb(),
                                                              const ConnectionDetail& connectionDetail = ConnectionDetail());
std::shared_ptr<SslWebsocketSession> make_websocket_session(uint64_t id, boost::beast::ssl_stream<boost::beast::tcp_stream>&& stream, Request&& req,
                                                            WebsocketConnectCb connectCb = WebsocketConnectCb(),
                                                            WebsocketReadCb readCb = WebsocketReadCb(),
                                                            const ConnectionDetail& connectionDetail = ConnectionDetail());


} // namespace Stalk
