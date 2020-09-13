#ifndef stalk_websocket_session_impl_INCLUDED
#define stalk_websocket_session_impl_INCLUDED

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
#if BOOST_BEAST_VERSION < 219
#include <boost/beast/experimental/core/ssl_stream.hpp>
#else
#include <boost/beast/ssl.hpp>
#endif
#include "stalk_types_internal.h"
#include "stalk/stalk_logger.h"


namespace Stalk
{

class WebsocketSessionImpl
{
public:

    // Construct the session
    explicit WebsocketSessionImpl(uint64_t id, Strand&& strand);//executor_context& ioc);
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

    virtual void start_timer() = 0;
    virtual void do_timeout() = 0;
    virtual void do_accept(Request&& req) = 0;

    void on_accept(boost::system::error_code ec);
    // Called when the timer expires.
    void on_timer(boost::system::error_code ec);

    // Called to indicate activity from the remote peer
    void activity();
    // Called after a ping is sent.
    void on_ping(boost::system::error_code ec);
    void on_control_callback(boost::beast::websocket::frame_type kind, boost::beast::string_view payload);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

protected:

    virtual std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const = 0;
    virtual std::shared_ptr<WebsocketSessionImpl> sharedFromThis() = 0;
    virtual void do_ping() = 0;
    virtual void do_read() = 0;
    virtual void do_write() = 0;
    virtual void set_control_callback() = 0;
    virtual bool is_open() const = 0;
    void on_send(std::shared_ptr<const std::string> msg);
    void on_write(const boost::system::error_code& ec, std::size_t bytes_transferred);

    void connectCb(bool connected);
    void readCb(std::string&& msg);

    uint64_t id_;
    WebsocketConnectCb connectCb_;
    WebsocketReadCb readCb_;
    Strand strand_;
    boost::asio::steady_timer timer_;
    LogPtr logger_;
    Request acceptedRequest_;
    bool close_ = false;

    boost::beast::multi_buffer rxBuffer_;
    std::deque<std::shared_ptr<const std::string>> sendQueue_;
    char ping_state_ = 0;
    ConnectionDetail connectionDetail_;
};


// Handles a plain WebSocket connection
class PlainWebsocketSession : public WebsocketSessionImpl, public std::enable_shared_from_this<PlainWebsocketSession>
{
public:
    // Create the session
    explicit PlainWebsocketSession(uint64_t id, boost::asio::ip::tcp::socket socket, const ConnectionDetail& connectionDetails);

    void stop() override;
    bool send(const std::string& msg) override;
    void start_timer() override;
    void do_timeout() override;
    void on_close(boost::system::error_code ec);

    boost::beast::websocket::stream<boost::asio::ip::tcp::socket>& stream() { return ws_; }
    const boost::beast::websocket::stream<boost::asio::ip::tcp::socket>& stream() const { return ws_; }

protected:
    std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<WebsocketSessionImpl> sharedFromThis() override { return shared_from_this(); }

    bool is_open() const override;
    void set_control_callback() override;
    void do_accept(Request&& req) override;
    void do_ping() override;
    void do_read() override;
    void do_write() override;

private:
    boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws_;
};


// Handles an SSL WebSocket connection
class SslWebsocketSession : public WebsocketSessionImpl, public std::enable_shared_from_this<SslWebsocketSession>
{
public:
    // Create the http_session
    explicit SslWebsocketSession(uint64_t id, boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream, const ConnectionDetail& connectionDetails);

    void stop() override;
    bool send(const std::string& msg) override;
    void start_timer() override;
    void do_eof();
    void on_shutdown(boost::system::error_code ec);

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>>& stream() { return ws_; }
    const boost::beast::websocket::stream<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>>& stream() const { return ws_; }

protected:
    std::shared_ptr<const WebsocketSessionImpl> sharedFromThis() const override { return shared_from_this(); }
    std::shared_ptr<WebsocketSessionImpl> sharedFromThis() override { return shared_from_this(); }

    void do_timeout() override;
    void set_control_callback() override;
    bool is_open() const override;
    // Start the asynchronous operation
    void do_accept(Request&& req) override;
    void do_ping() override;
    void do_read() override;
    void do_write() override;

private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>> ws_;
    bool eof_ = false;
};

std::shared_ptr<PlainWebsocketSession> make_websocket_session(uint64_t id, boost::asio::ip::tcp::socket socket, Request&& req,
                                                              WebsocketConnectCb connectCb = WebsocketConnectCb(),
                                                              WebsocketReadCb readCb = WebsocketReadCb(),
                                                              const ConnectionDetail& connectionDetail = ConnectionDetail());
std::shared_ptr<SslWebsocketSession> make_websocket_session(uint64_t id, boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream, Request&& req,
                                                            WebsocketConnectCb connectCb = WebsocketConnectCb(),
                                                            WebsocketReadCb readCb = WebsocketReadCb(),
                                                            const ConnectionDetail& connectionDetail = ConnectionDetail());


} // namespace Stalk

#endif
