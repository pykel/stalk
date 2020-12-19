#include "stalk_websocket_session_impl.h"
#include "stalk_request_impl.h"
#include "stalk/stalk_connection_detail_ostream.h"

namespace Stalk
{


WebsocketSessionImpl::WebsocketSessionImpl(uint64_t id) :
    id_(id),
    logger_(Logger::get("WebServer.WebsocketSession." + std::to_string(reinterpret_cast<uint64_t>(id))))
{
}

WebsocketSessionImpl::~WebsocketSessionImpl()
{
    logger_->trace("~WebsocketSession()");
}

uint64_t WebsocketSessionImpl::id() const
{
    return id_;
}

// Start the asynchronous operation
void WebsocketSessionImpl::run(Request&& req)
{
    logger_->trace("run()");
    // Accept the WebSocket upgrade request
    do_accept(std::move(req));
}

WebsocketSessionImpl& WebsocketSessionImpl::setConnectCb(WebsocketConnectCb cb)
{
    connectCb_ = cb;
    return *this;
}

WebsocketSessionImpl& WebsocketSessionImpl::setReadCb(WebsocketReadCb cb)
{
    readCb_ = cb;
    return *this;
}

const ConnectionDetail& WebsocketSessionImpl::connectionDetail() const
{
    return connectionDetail_;
}

const Request& WebsocketSessionImpl::request() const
{
    return acceptedRequest_;
}

Request& WebsocketSessionImpl::request()
{
    return acceptedRequest_;
}

void WebsocketSessionImpl::on_accept(boost::system::error_code ec)
{
    if (ec)
    {
        logger_->error("on_accept: {}", ec.message());
        connectCb(false);
    }
    else
    {
        logger_->trace("on_accept: {}", ec.message());
        connectCb(true);
        do_read();
    }
}

void WebsocketSessionImpl::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
{
    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted)
    {
        logger_->debug("on_read: {}", ec.message());
        close_ = true;
        connectCb(false);
        return;
    }

    // This indicates that the websocket_session was closed
    if (ec == boost::beast::websocket::error::closed)
    {
        logger_->debug("on_read: {}", ec.message());
        close_ = true;
        connectCb(false);
        return;
    }

    if (ec)
    {
        logger_->debug("on_read: {}", ec.message());
        close_ = true;
        connectCb(false);
        return;
    }

    std::string msg = boost::beast::buffers_to_string(rxBuffer_.data());
    rxBuffer_.consume(rxBuffer_.size());
    readCb(std::move(msg));

    do_read();
}

void WebsocketSessionImpl::on_send(std::shared_ptr<const std::string> msg)
{
    sendQueue_.push_back(msg);

    // Already sending?
    if (sendQueue_.size() > 1)
        return;

    do_write();
}

void WebsocketSessionImpl::on_write(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    logger_->trace("on_write: bytes_transferred:{}", bytes_transferred);
    if (ec)
    {
        logger_->error("on_write: {}", ec.message());
        return;
    }

    sendQueue_.pop_front();
    do_write();
}

void WebsocketSessionImpl::connectCb(bool connected)
{
    if (connectCb_)
    {
        connectCb_(sharedFromThis(), connected);
    }
}

void WebsocketSessionImpl::readCb(std::string&& msg)
{
    if (readCb_)
    {
        readCb_(sharedFromThis(), std::move(msg));
    }
}

//----------------------------------------------------------------------------

PlainWebsocketSession::PlainWebsocketSession(uint64_t id, boost::beast::tcp_stream&& stream, const ConnectionDetail& connectionDetails) :
    WebsocketSessionImpl(id),
    ws_(std::move(stream))
{
    connectionDetail_ = connectionDetails;
    logger_->debug("PlainWebsocketSession: from:{}", connectionDetail_);
}

void PlainWebsocketSession::stop()
{
    do_stop();
}

bool PlainWebsocketSession::send(const std::string& msg)
{
    logger_->trace("send: msg.size:{}", msg.size());

    // post message via executor ready for sending
    auto msgPtr = std::make_shared<const std::string>(msg);
    boost::beast::net::post(
        ws_.get_executor(),
        boost::beast::bind_front_handler(
            &PlainWebsocketSession::on_send,
            shared_from_this(),
            msgPtr));
    return true;
}

void PlainWebsocketSession::do_stop()
{
    logger_->trace("do_stop");

    // This is so the close can have a timeout
    if (close_)
        return;
    close_ = true;

    // Close the WebSocket Connection
    ws_.async_close(
        boost::beast::websocket::close_code::normal,
        boost::asio::bind_executor(
            ws_.get_executor(),
            std::bind(
                &PlainWebsocketSession::on_close,
                shared_from_this(),
                std::placeholders::_1)));
}

void PlainWebsocketSession::on_close(boost::system::error_code ec)
{
    if (ec)
    {
        logger_->error("on_close: {}", ec.message());
        return;
    }
    logger_->trace("on_close: {}", ec.message());

    // At this point the connection is gracefully closed
}

bool PlainWebsocketSession::is_open() const
{
    return ws_.is_open();
}

void PlainWebsocketSession::do_accept(Request&& req)
{
    logger_->trace("do_accept");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    boost::beast::get_lowest_layer(ws_).expires_never();

    // Set suggested timeout settings for the websocket
    ws_.set_option(
        boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::server));

    acceptedRequest_ = std::move(req);

    ws_.async_accept(
        acceptedRequest_.impl->request,
        boost::beast::bind_front_handler(
            &WebsocketSessionImpl::on_accept,
            shared_from_this()));
}

void PlainWebsocketSession::do_read()
{
    logger_->trace("do_read");

    // Read a message into our buffer
    ws_.async_read(
        rxBuffer_,
        boost::beast::bind_front_handler(
            &WebsocketSessionImpl::on_read,
            shared_from_this()));
}

void PlainWebsocketSession::do_write()
{
    logger_->trace("do_write");
    if (sendQueue_.empty())
        return;

    //const std::shared_ptr<const std::string>& msg = sendQueue_.front();

    const std::string& msg = *(sendQueue_.front());
    logger_->trace("do_write: {} bytes", msg.size());

    ws_.async_write(
        boost::beast::net::buffer(msg),
        boost::beast::bind_front_handler(
            &PlainWebsocketSession::on_write,
            shared_from_this()));
}

//----------------------------------------------------------------------------

SslWebsocketSession::SslWebsocketSession(uint64_t id, boost::beast::ssl_stream<boost::beast::tcp_stream>&& stream,
                                         const ConnectionDetail& connectionDetail) :
    WebsocketSessionImpl(id),
    ws_(std::move(stream))
{
    connectionDetail_ = connectionDetail;
    logger_->debug("SslWebsocketSession: from:{}", connectionDetail_);
}

void SslWebsocketSession::stop()
{
    do_stop();
}

bool SslWebsocketSession::send(const std::string& msg)
{
    logger_->trace("send: msg.size:{}", msg.size());

    // post message via executor ready for sending
    auto msgPtr = std::make_shared<const std::string>(msg);

    boost::beast::net::post(
        ws_.get_executor(),
        boost::beast::bind_front_handler(
            &SslWebsocketSession::on_send,
            shared_from_this(),
            msgPtr));

    return true;
}

void SslWebsocketSession::do_eof()
{
    eof_ = true;

    // Close the WebSocket connection
    ws_.async_close(boost::beast::websocket::close_code::normal,
        boost::beast::bind_front_handler(
            &SslWebsocketSession::on_shutdown,
            shared_from_this()));

}

void SslWebsocketSession::on_shutdown(boost::system::error_code ec)
{
    // Happens when the shutdown times out
    if(ec == boost::asio::error::operation_aborted)
    {
        logger_->error("on_shutdown: {}", ec.message());
        return;
    }

    if(ec)
    {
        logger_->error("on_shutdown: {}", ec.message());
    }

    // At this point the connection is closed gracefully
}

void SslWebsocketSession::do_stop()
{
    // If this is true it means we timed out performing the shutdown
    if (eof_)
        return;

    do_eof();
}

bool SslWebsocketSession::is_open() const
{
    return ws_.is_open();
}

// Start the asynchronous operation
void SslWebsocketSession::do_accept(Request&& req)
{
    logger_->trace("do_accept");

    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    boost::beast::get_lowest_layer(ws_).expires_never();

    // Set suggested timeout settings for the websocket
    ws_.set_option(
        boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::server));

    acceptedRequest_ = std::move(req);

    ws_.async_accept(
        acceptedRequest_.impl->request,
        boost::beast::bind_front_handler(
            &WebsocketSessionImpl::on_accept,
            shared_from_this()));
}

void SslWebsocketSession::do_read()
{
    logger_->trace("do_read");

    ws_.async_read(
        rxBuffer_,
        boost::beast::bind_front_handler(
            &WebsocketSessionImpl::on_read,
            shared_from_this()));
}

void SslWebsocketSession::do_write()
{
    logger_->trace("do_write");
    if (sendQueue_.empty())
        return;

    const std::string& msg = *sendQueue_.front();
    logger_->trace("do_write: {} bytes", msg.size());

    ws_.async_write(
        boost::beast::net::buffer(msg),
        boost::beast::bind_front_handler(
            &SslWebsocketSession::on_write,
            shared_from_this()));
}

std::shared_ptr<PlainWebsocketSession> make_websocket_session(uint64_t id, boost::beast::tcp_stream&& stream, Request&& req,
                                                              WebsocketConnectCb connectCb,
                                                              WebsocketReadCb readCb,
                                                              const ConnectionDetail& connectionDetail)
{
    auto session = std::make_shared<PlainWebsocketSession>(id, std::move(stream), connectionDetail);
    session->setConnectCb(connectCb);
    session->setReadCb(readCb);
    session->run(std::move(req));
    return session;
}

std::shared_ptr<SslWebsocketSession> make_websocket_session(uint64_t id, boost::beast::ssl_stream<boost::beast::tcp_stream>&& stream, Request&& req,
                                                            WebsocketConnectCb connectCb,
                                                            WebsocketReadCb readCb,
                                                            const ConnectionDetail& connectionDetail)
{
    auto session = std::make_shared<SslWebsocketSession>(id, std::move(stream), connectionDetail);
    session->setConnectCb(connectCb);
    session->setReadCb(readCb);
    session->run(std::move(req));
    return session;
}

} // namespace Stalk
