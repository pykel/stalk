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
#include "stalk/stalk_logger.h"

namespace Stalk
{

// Construct the session
HttpSession::HttpSession(uint64_t id, Strand&& strand, boost::beast::flat_buffer buffer) :
    id_(id),
    strand_(std::move(strand)),
    timer_(static_cast<boost::asio::io_context&>(strand_.context()), (std::chrono::steady_clock::time_point::max)()),
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

void HttpSession::cancelTimer()
{
    boost::system::error_code ignoredEc;
    timer_.cancel(ignoredEc);
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
    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    req_ = BeastRequest();

    do_read();
}

// Called when the timer expires.
void HttpSession::on_timer(boost::system::error_code ec)
{
    if (ec && ec != boost::asio::error::operation_aborted)
    {
        logger_->error("on_timer: {}", ec.message());
        return;
    }

    if (ec)
        return;

    // Verify that the timer really expired since the deadline may have moved.
    if (timer_.expiry() <= std::chrono::steady_clock::now())
        return do_timeout();

    start_timer();
}

void HttpSession::on_read(boost::system::error_code ec)
{
    if (ec)
    {
        logger_->debug("on_read: {}", ec.message());
    }

    // This means they closed the connection
    if (ec == boost::beast::http::error::end_of_stream)
    {
        cancelTimer();
        return do_eof();
    }

    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted)
    {
        cancelTimer();
        return;
    }

    if (ec)
    {
        cancelTimer();
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
#if 0
            std::weak_ptr<HttpSession> self = sharedFromThis();
            auto sendResp = [self](Response&& resp)
            {
                if (self.expired())
                    return;

                auto session = self.lock();
                if (session)
                {
                    session->write(std::move(resp.impl->response));
                }
            };
#endif
            auto upgrade = [self](Request&& req)
            {
                auto session = self.lock();
                if (session)
                {
                    session->do_websocket_upgrade(std::move(req));
                }
            };

            websocketPreUpgradeCb_(connectionDetail_, std::move(stalkRequest_), std::move(sendResp), std::move(upgrade));
#if 0
            std::optional<Response> resp = websocketPreUpgradeCb_(req_);
            if (resp)
            {
                resp->keep_alive(false);
                write(std::move(resp.value()));
                return;
            }
#endif
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
#if 0
    // Send the response
    handle_request(std::move(stalkRequest_));
#endif
    // If we aren't at the queue limit, try to pipeline another request
    const size_t MaxQueuedResponses = 8;
    if (responses_.size() < MaxQueuedResponses)
        start_read();
}

void HttpSession::on_write(boost::system::error_code ec, bool close)
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

PlainHttpSession::PlainHttpSession(uint64_t id, boost::asio::ip::tcp::socket socket, boost::beast::flat_buffer buffer) :
//#if BOOST_ASIO_VERSION < 101400
//    HttpSession(socket.get_executor().context(), std::move(buffer)),
//#else
    HttpSession(id, boost::asio::make_strand(socket.get_executor()), std::move(buffer)),
//#endif
    socket_(std::move(socket))
{
    connectionDetail_ = ConnectionDetailBuilder::build(id, stream());
}

boost::asio::ip::tcp::socket& PlainHttpSession::stream()
{
    return socket_;
}

boost::asio::ip::tcp::socket PlainHttpSession::release_stream()
{
    return std::move(socket_);
}

// Start the asynchronous operation
void PlainHttpSession::run()
{
    // Run the timer. The timer is operated
    // continuously, this simplifies the code.
    on_timer({});
    start_read();
}

void PlainHttpSession::do_eof()
{
    // Send a TCP shutdown
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
}

void PlainHttpSession::do_read()
{
    // Read a request
    boost::beast::http::async_read(
                stream(),
                buffer_,
                req_,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &HttpSession::on_read,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void PlainHttpSession::do_timeout()
{
    // Closing the socket cancels all outstanding operations. They
    // will complete with boost::asio::error::operation_aborted
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

void PlainHttpSession::do_write()
{
    if (responses_.empty())
        return;

    auto& resp = responses_.front().impl->response;

    boost::beast::http::async_write(
                stream(),
                resp,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &HttpSession::on_write,
                        shared_from_this(),
                        std::placeholders::_1,
                        resp.need_eof())));
}

void PlainHttpSession::start_timer()
{
    // Wait on the timer
    timer_.async_wait(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &HttpSession::on_timer,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void PlainHttpSession::do_websocket_upgrade(Request&& req)
{
    auto session = make_websocket_session(id(), release_stream(), std::move(req),
                                          websocketConnectCb_, websocketReadCb_,
                                          connectionDetail_);
}


//----------------------------------------------------------------------------

// Create the http_session
SslHttpSession::SslHttpSession(uint64_t id, boost::asio::ip::tcp::socket socket, boost::asio::ssl::context& ctx, boost::beast::flat_buffer buffer) :
    HttpSession(id, boost::asio::make_strand(socket.get_executor()), std::move(buffer)),
    stream_(std::move(socket), ctx)
{
    connectionDetail_ = ConnectionDetailBuilder::build(id, stream());
    logger_->debug("SslHttpSession: from:{}", connectionDetail_);
}

boost::beast::ssl_stream<boost::asio::ip::tcp::socket>& SslHttpSession::stream() { return stream_; }
boost::beast::ssl_stream<boost::asio::ip::tcp::socket> SslHttpSession::release_stream() { return std::move(stream_); }

// Start the asynchronous operation
void SslHttpSession::run()
{
    on_timer({});
    timer_.expires_after(std::chrono::seconds(15));

    // Perform the SSL handshake
    // Note, this is the buffered version of the handshake.
    stream_.async_handshake(
        boost::asio::ssl::stream_base::server,
        buffer_.data(),
        boost::asio::bind_executor(
            strand_,
            std::bind(
                &SslHttpSession::on_handshake,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2)));
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

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Perform the SSL shutdown
    stream_.async_shutdown(
        boost::asio::bind_executor(
            strand_,
            std::bind(
                &SslHttpSession::on_shutdown,
                shared_from_this(),
                std::placeholders::_1)));
}

void SslHttpSession::on_shutdown(boost::system::error_code ec)
{
    boost::system::error_code ignoredEc;
#if BOOST_BEAST_VERSION < 219
    stream_.lowest_layer().cancel(ignoredEc);
    stream_.lowest_layer().close(ignoredEc);
#else
    stream_.next_layer().cancel(ignoredEc);
    stream_.next_layer().close(ignoredEc);
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
    boost::beast::http::async_read(
        stream(),
        buffer_,
        req_,
        boost::asio::bind_executor(
            strand_,
            std::bind(
                &HttpSession::on_read,
                shared_from_this(),
                std::placeholders::_1)));
}

void SslHttpSession::do_write()
{
    if (responses_.empty())
        return;

    auto& resp = responses_.front().impl->response;

    boost::beast::http::async_write(
        stream(),
        resp,
        boost::asio::bind_executor(
            strand_,
            std::bind(
                &HttpSession::on_write,
                shared_from_this(),
                std::placeholders::_1,
                resp.need_eof())));
}

void SslHttpSession::do_timeout()
{
    // If this is true it means we timed out performing the shutdown
    if (eof_)
        return;

    // Start the timer again
    timer_.expires_at((std::chrono::steady_clock::time_point::max)());
    on_timer({});
    do_eof();
}

void SslHttpSession::start_timer()
{
    // Wait on the timer
    timer_.async_wait(
        boost::asio::bind_executor(
            strand_,
            std::bind(
                &HttpSession::on_timer,
                shared_from_this(),
                std::placeholders::_1)));
}

void SslHttpSession::do_websocket_upgrade(Request&& req)
{
    auto session = make_websocket_session(id(), release_stream(), std::move(req),
                                          websocketConnectCb_, websocketReadCb_,
                                          connectionDetail_);
}


} // namespace Stalk
