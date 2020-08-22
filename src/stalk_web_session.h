#ifndef stalk_web_session_INCLUDED
#define stalk_web_session_INCLUDED

#include <stdint.h>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#if BOOST_BEAST_VERSION < 219
#include <boost/beast/experimental/core/ssl_stream.hpp>
#else
#include <boost/beast/ssl.hpp>
#endif
#include "stalk/stalk_types.h"
#include "stalk_types_internal.h"
#include "logger.h"
#include "stalk/stalk_request.h"
#include "stalk/stalk_connection_detail.h"

namespace Stalk
{


// Base class for plain & ssl sessions
class HttpSession
{
public:

    HttpSession(uint64_t id, Strand&& strand/*executor_context& ioc*/, boost::beast::flat_buffer buffer);
    virtual ~HttpSession();

    HttpSession& setWebsocketPreUpgradeCb(WebsocketPreUpgradeCb cb);
    HttpSession& setWebsocketConnectCb(WebsocketConnectCb cb);
    HttpSession& setWebsocketReadCb(WebsocketReadCb cb);
    HttpSession& setHttpReqCb(HttpRequestCb cb);

    uint64_t id() const;
    const ConnectionDetail& connectionDetail() const;

    virtual void run() = 0;

    void handle_request(Stalk::Request&& req);
    void write(Response&& resp);
    void start_read();
    void on_timer(boost::system::error_code ec);
    void on_read(boost::system::error_code ec);
    void on_write(boost::system::error_code ec, bool close);

protected:

    virtual std::shared_ptr<const HttpSession> sharedFromThis() const = 0;
    virtual std::shared_ptr<HttpSession> sharedFromThis() = 0;
    virtual void do_read() = 0;
    virtual void do_write() = 0;
    virtual void do_eof() = 0;
    virtual void do_timeout() = 0;
    virtual void start_timer() = 0;
    virtual void do_websocket_upgrade(Request&& req) = 0;
    void cancelTimer();
    void requestCb(Request&& request);

    uint64_t id_;
    Strand strand_;
    boost::asio::steady_timer timer_;
    boost::beast::flat_buffer buffer_;
    std::shared_ptr<spdlog::logger> logger_;
    std::vector<Response> responses_;
    BeastRequest req_;
    BeastResponse response_;
    WebsocketPreUpgradeCb websocketPreUpgradeCb_;
    WebsocketConnectCb websocketConnectCb_;
    WebsocketReadCb websocketReadCb_;
    HttpRequestCb httpRequestCb_;

    Stalk::Request stalkRequest_;
    Stalk::ConnectionDetail connectionDetail_;
}; // class http_session


// Handles a plain HTTP connection
class PlainHttpSession : public HttpSession, public std::enable_shared_from_this<PlainHttpSession>
{
public:
    // Create the http_session
    PlainHttpSession(uint64_t id, boost::asio::ip::tcp::socket socket, boost::beast::flat_buffer buffer);

    boost::asio::ip::tcp::socket& stream();
    boost::asio::ip::tcp::socket release_stream();

    // Start the asynchronous operation
    void run() override;

protected:

    std::shared_ptr<const HttpSession> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<HttpSession> sharedFromThis() override { return shared_from_this(); }

    void do_eof() override;
    void do_read() override;
    void do_timeout() override;
    void do_write() override;
    void start_timer() override;
    void do_websocket_upgrade(Request&& req) override;

private:

    boost::asio::ip::tcp::socket socket_;
}; // class plain_http_session


// Handles an SSL HTTP connection
class SslHttpSession : public HttpSession, public std::enable_shared_from_this<SslHttpSession>
{
public:
    // Create the http_session
    SslHttpSession(
        uint64_t id,
        boost::asio::ip::tcp::socket socket,
        boost::asio::ssl::context& ctx,
        boost::beast::flat_buffer buffer);

    boost::beast::ssl_stream<boost::asio::ip::tcp::socket>& stream();
    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> release_stream();

    // Start the asynchronous operation
    void run() override;
    void on_handshake(boost::system::error_code ec, std::size_t bytes_used);
    void on_shutdown(boost::system::error_code ec);

protected:

    std::shared_ptr<const HttpSession> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<HttpSession> sharedFromThis() override { return shared_from_this(); }

    void do_eof() override;
    void do_read() override;
    void do_write() override;
    void do_timeout() override;
    void start_timer() override;
    void do_websocket_upgrade(Request&& req) override;

private:

    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream_;
    bool eof_ = false;

}; // class ssl_http_session


} // namespace Stalk

#endif
