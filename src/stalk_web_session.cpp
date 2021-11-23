#include "stalk_web_session.h"
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include "stalk/stalk_websocket_session.h"
#include "stalk/stalk_connection_detail.h"
#include "stalk_connection_detail_builder.h"
#include "stalk_request_impl.h"
#include "stalk_response_impl.h"
#include "stalk_websocket_session_impl.h"
#include "stalk/stalk_connection_detail_ostream.h"
#include "stalk_logger.h"

namespace Stalk
{

// Construct the session
HttpSession::HttpSession(uint64_t id, boost::beast::flat_buffer buffer) :
    id_(id),
    buffer_(std::move(buffer)),
    logger_(Logger::get("WebServer.HttpSession." + std::to_string(reinterpret_cast<uint64_t>(id))))
{
    logger_->trace("HttpSession()");
}

HttpSession::~HttpSession()
{
    logger_->trace("~HttpSession()");
}

HttpSession& HttpSession::setWebsocketPreUpgradeCb(WebsocketPreUpgradeCb cb)
{
    websocketPreUpgradeCb_ = cb;
    return *this;
}

HttpSession& HttpSession::setWebsocketConnectCb(WebsocketConnectCb cb)
{
    websocketConnectCb_ = cb;
    return *this;
}

HttpSession& HttpSession::setWebsocketReadCb(WebsocketReadCb cb)
{
    websocketReadCb_ = cb;
    return *this;
}

HttpSession& HttpSession::setHttpReqCb(HttpRequestCb cb)
{
    httpRequestCb_ = cb;
    return *this;
}

uint64_t HttpSession::id() const
{
    return id_;
}

const ConnectionDetail& HttpSession::connectionDetail() const
{
    return connectionDetail_;
}

void HttpSession::write(Response&& resp)
{
    responses_.push_back(std::move(resp));
    if (responses_.size() == 1)
    {
        do_write();
    }
}

void HttpSession::start_read()
{
    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    req_ = BeastRequest();

    do_read();
}

void HttpSession::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
{
    if (ec)
    {
        logger_->debug("on_read: {}", ec.message());
    }

    // This means they closed the connection
    if (ec == boost::beast::http::error::end_of_stream)
    {
        return do_eof();
    }

    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted)
    {
        return;
    }

    if (ec)
    {
        return;
    }

    // Response sending lambda - weak ptr because may be destructed before someone calls this func
    std::weak_ptr<HttpSession> self = sharedFromThis();
    auto sendResp = [self](Response&& resp)
        {
            if (self.expired())
                return;

            auto session = self.lock();
            if (session)
            {
                resp.impl->response.prepare_payload();

                session->write(std::move(resp));
            }
        };

    const bool isWebsocketUpgrade = boost::beast::websocket::is_upgrade(req_);
    stalkRequest_ = Request(std::make_unique<RequestImpl>(std::move(req_)));

    // See if it is a WebSocket Upgrade
    if (isWebsocketUpgrade)
    {
        if (websocketPreUpgradeCb_)
        {
            logger_->trace("on_read: websocketPreUpgradeCb");

            auto upgrade = [self, this](Request&& req)
            {
                auto session = self.lock();
                if (session)
                {
                    logger_->trace("on_read: upgrade: session calling do_websocket_upgrade {}", req);
                    session->do_websocket_upgrade(std::move(req));
                }
            };

            websocketPreUpgradeCb_(connectionDetail_, std::move(stalkRequest_), std::move(sendResp), std::move(upgrade));
        }
        else
        {
            // Transfer the stream to a new WebSocket session
            do_websocket_upgrade(std::move(stalkRequest_));
        }
        return;
    }

    // Pass request to assigned callback
    if (httpRequestCb_)
    {
        std::weak_ptr<HttpSession> self = sharedFromThis();
        httpRequestCb_(connectionDetail_, std::move(stalkRequest_), sendResp);
    }

    // If we aren't at the queue limit, try to pipeline another request
    const size_t MaxQueuedResponses = 8;
    if (responses_.size() < MaxQueuedResponses)
        start_read();
}

void HttpSession::on_write(bool close, boost::system::error_code ec, std::size_t bytes_transferred)
{
    // Happens when the timer closes the socket
    if(ec == boost::asio::error::operation_aborted)
        return;

    if (ec)
    {
        logger_->error("on_write: {}", ec.message());
        return;
    }

    if (close)
    {
        // This means we should close the connection, usually because
        // the response indicated the "Connection: close" semantic.
        return do_eof();
    }

    const size_t MaxQueuedResponses = 8;
    bool wasFull = responses_.size() == MaxQueuedResponses;
    responses_.erase(responses_.begin());
    do_write();
    if (wasFull)
        start_read();
}

//----------------------------------------------------------------------------

PlainHttpSession::PlainHttpSession(uint64_t id, boost::beast::tcp_stream&& stream, boost::beast::flat_buffer buffer) :
    HttpSession(id, std::move(buffer)),
    stream_(std::move(stream))
{
    connectionDetail_ = ConnectionDetailBuilder::build(id, stream_.socket());
}

boost::beast::tcp_stream& PlainHttpSession::stream()
{
    return stream_;
}

boost::beast::tcp_stream PlainHttpSession::release_stream()
{
    return std::move(stream_);
}

// Start the asynchronous operation
void PlainHttpSession::run()
{
    start_read();
}

void PlainHttpSession::do_eof()
{
    // Send a TCP shutdown
    boost::system::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
}

void PlainHttpSession::do_read()
{
    // Set the timeout.
    boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    boost::beast::http::async_read(
        stream(),
        buffer_,
        req_,
        boost::beast::bind_front_handler(
            &HttpSession::on_read,
            shared_from_this()));
}

void PlainHttpSession::do_shutdown()
{
    // Closing the socket cancels all outstanding operations. They
    // will complete with boost::asio::error::operation_aborted
    boost::system::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    stream_.socket().close(ec);
}

void PlainHttpSession::do_write()
{
    if (responses_.empty())
        return;

    auto& resp = responses_.front().impl->response;

    boost::beast::http::async_write(
        stream(),
        resp,
        boost::beast::bind_front_handler(
            &HttpSession::on_write,
            shared_from_this(),
            resp.need_eof()));
}


void PlainHttpSession::do_websocket_upgrade(Request&& req)
{
    auto session = make_websocket_session(id(), release_stream(), std::move(req),
                                          websocketConnectCb_, websocketReadCb_,
                                          connectionDetail_);
}


//----------------------------------------------------------------------------

// Create the http_session
SslHttpSession::SslHttpSession(uint64_t id, boost::beast::tcp_stream&& stream, boost::asio::ssl::context& ctx, boost::beast::flat_buffer buffer) :
    HttpSession(id, std::move(buffer)),
    stream_(std::move(stream), ctx)
{
    connectionDetail_ = ConnectionDetailBuilder::build(id, stream_);
    logger_->debug("SslHttpSession: from:{}", connectionDetail_);
}

boost::beast::ssl_stream<boost::beast::tcp_stream>& SslHttpSession::stream() { return stream_; }
boost::beast::ssl_stream<boost::beast::tcp_stream> SslHttpSession::release_stream() { return std::move(stream_); }

// Start the asynchronous operation
void SslHttpSession::run()
{
    // Set the timeout.
    boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    // Note, this is the buffered version of the handshake.
    stream_.async_handshake(
        boost::asio::ssl::stream_base::server,
        buffer_.data(),
        boost::beast::bind_front_handler(
            &SslHttpSession::on_handshake,
            shared_from_this()));
}

void SslHttpSession::on_handshake(boost::system::error_code ec, std::size_t bytes_used)
{
    if (ec)
    {
        logger_->error("on_handshake: {}", ec.message());
        return;
    }

    // Consume the portion of the buffer used by the handshake
    buffer_.consume(bytes_used);

    connectionDetail_ = ConnectionDetailBuilder::build(id(), stream());
    logger_->debug("on_handshake: connectionDetail:{}", connectionDetail_);

    start_read();
}

void SslHttpSession::do_eof()
{
    eof_ = true;

    stream_.async_shutdown(
        boost::beast::bind_front_handler(
            &SslHttpSession::on_shutdown,
            shared_from_this()));
}

void SslHttpSession::on_shutdown(boost::system::error_code ec)
{
    boost::system::error_code ignoredEc;
#if BOOST_BEAST_VERSION < 219
    stream_.lowest_layer().cancel(ignoredEc);
    stream_.lowest_layer().close(ignoredEc);
#else
    stream_.next_layer().socket().cancel(ignoredEc);
    stream_.next_layer().socket().close(ignoredEc);
#endif
    // Happens when the shutdown times out
    if (ec == boost::asio::error::operation_aborted)
    {
        logger_->error("on_shutdown: {}", ec.message());
        return;
    }

    if (ec)
    {
        logger_->error("on_shutdown: {}", ec.message());
        return;
    }

    // At this point the connection is closed gracefully
}

void SslHttpSession::do_read()
{
    boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    boost::beast::http::async_read(
        stream(),
        buffer_,
        req_,
        boost::beast::bind_front_handler(
            &HttpSession::on_read,
                    shared_from_this()));
}

void SslHttpSession::do_write()
{
    if (responses_.empty())
        return;

    auto& resp = responses_.front().impl->response;

    boost::beast::http::async_write(
        stream(),
        resp,
        boost::beast::bind_front_handler(
            &HttpSession::on_write,
            shared_from_this(),
            resp.need_eof()));
}

void SslHttpSession::do_shutdown()
{
    // If this is true it means we timed out performing the shutdown
    if (eof_)
        return;

    do_eof();
}

void SslHttpSession::do_websocket_upgrade(Request&& req)
{
    auto session = make_websocket_session(id(), release_stream(), std::move(req),
                                          websocketConnectCb_, websocketReadCb_,
                                          connectionDetail_);
}


} // namespace Stalk
