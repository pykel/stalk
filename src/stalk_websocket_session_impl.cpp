#include "stalk_websocket_session_impl.h"
#include "stalk_request_impl.h"
#include "stalk/stalk_connection_detail_ostream.h"

namespace Stalk
{


WebsocketSessionImpl::WebsocketSessionImpl(uint64_t id, Strand&& strand) :
    id_(id),
    strand_(std::move(strand)),
    timer_(static_cast<boost::asio::io_context&>(strand_.context()), (std::chrono::steady_clock::time_point::max)()),
    logger_(Logger::get(std::string("WebServer.WebsocketSession.") + std::to_string(reinterpret_cast<uint64_t>(this))))
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
    // Run the timer. The timer is operated
    // continuously, this simplifies the code.
    on_timer({});

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
        connectCb(true);
        do_read();
    }
}

// Called when the timer expires.
void WebsocketSessionImpl::on_timer(boost::system::error_code ec)
{
    if (ec)// && ec != boost::asio::error::operation_aborted)
    {
        if (ec != boost::asio::error::operation_aborted)
            logger_->error("on_timer: {}", ec.message());
        return;
    }

    logger_->trace("on_timer: {}", ec.message());

    // See if the timer really expired since the deadline may have moved.
    if (timer_.expiry() <= std::chrono::steady_clock::now())
    {
        // If this is the first time the timer expired,
        // send a ping to see if the other end is there.
        if (is_open() && ping_state_ == 0)
        {
            // Note that we are sending a ping
            ping_state_ = 1;
            timer_.expires_after(std::chrono::seconds(15));
            do_ping();
        }
        else
        {
            // The timer expired while trying to handshake, or we sent a ping and it never completed or
            // we never got back a control frame, so close.
            do_timeout();
            return;
        }
    }

    start_timer();
}

// Called to indicate activity from the remote peer
void WebsocketSessionImpl::activity()
{
    // Note that the connection is alive
    ping_state_ = 0;

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));
}

// Called after a ping is sent.
void WebsocketSessionImpl::on_ping(boost::system::error_code ec)
{
    logger_->trace("on_ping");

    if (ec)
    {
        logger_->error("on_ping: {}", ec.message());
        return;
    }

    // Note that the ping was sent.
    if (ping_state_ == 1)
    {
        ping_state_ = 2;
    }
    else
    {
        // ping_state_ could have been set to 0
        // if an incoming control frame was received
        // at exactly the same time we sent a ping.
        BOOST_ASSERT(ping_state_ == 0);
    }
}

void WebsocketSessionImpl::on_control_callback(boost::beast::websocket::frame_type kind, boost::beast::string_view payload)
{
    boost::ignore_unused(kind, payload);
    // Note that there is activity
    activity();
}

void WebsocketSessionImpl::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
{
    //logger_->trace("on_read: bytes_transferred:{}", bytes_transferred);

    // Happens when the timer closes the socket
    if (ec == boost::asio::error::operation_aborted)
    {
        logger_->debug("on_read: {}", ec.message());
        timer_.cancel(ec);
        close_ = true;
        connectCb(false);
        return;
    }

    // This indicates that the websocket_session was closed
    if (ec == boost::beast::websocket::error::closed)
    {
        logger_->debug("on_read: {}", ec.message());
        timer_.cancel(ec);
        close_ = true;
        connectCb(false);
        return;
    }

    if (ec)
    {
        logger_->debug("on_read: {}", ec.message());
        timer_.cancel(ec);
        close_ = true;
        connectCb(false);
        return;
    }

    // Note that there is activity
    activity();

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

PlainWebsocketSession::PlainWebsocketSession(uint64_t id, boost::asio::ip::tcp::socket socket, const ConnectionDetail& connectionDetails) :
//#if BOOST_ASIO_VERSION < 101400
//    WebsocketSession(socket.get_executor().context()),
//#else
    WebsocketSessionImpl(id, boost::asio::make_strand(socket.get_executor())),
//#endif
    ws_(std::move(socket))
{
    connectionDetail_ = connectionDetails;
    logger_->debug("PlainWebsocketSession: from:{}", connectionDetail_);
}

void PlainWebsocketSession::stop()
{
    do_timeout();
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


void PlainWebsocketSession::start_timer()
{
    // Wait on the timer
    timer_.async_wait(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_timer,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void PlainWebsocketSession::do_timeout()
{
    logger_->trace("do_timeout");

    // This is so the close can have a timeout
    if (close_)
        return;
    close_ = true;

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Close the WebSocket Connection
    ws_.async_close(
                boost::beast::websocket::close_code::normal,
                boost::asio::bind_executor(
                    strand_,
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

void PlainWebsocketSession::set_control_callback()
{
    // Set the control callback. This will be called
    // on every incoming ping, pong, and close frame.
    ws_.control_callback(
                std::bind(
                    &WebsocketSessionImpl::on_control_callback,
                    this,
                    std::placeholders::_1,
                    std::placeholders::_2));
}

// Start the asynchronous operation
void PlainWebsocketSession::do_accept(Request&& req)
{
    acceptedRequest_ = std::move(req);

    set_control_callback();
    // Set the control callback. This will be called
    // on every incoming ping, pong, and close frame.
    ws_.control_callback(
                std::bind(
                    &WebsocketSessionImpl::on_control_callback,
                    this,
                    std::placeholders::_1,
                    std::placeholders::_2));

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Accept the websocket handshake
    ws_.async_accept(
                acceptedRequest_.impl->request,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_accept,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void PlainWebsocketSession::do_ping()
{
    // Now send the ping
    ws_.async_ping({},
                   boost::asio::bind_executor(
                       strand_,
                       std::bind(
                           &WebsocketSessionImpl::on_ping,
                           shared_from_this(),
                           std::placeholders::_1)));
}

void PlainWebsocketSession::do_read()
{
    logger_->trace("do_read");

    // Read a message into our buffer
    ws_.async_read(
                rxBuffer_,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2)));
}

void PlainWebsocketSession::do_write()
{
    logger_->trace("do_write");
    if (sendQueue_.empty())
        return;

    //const std::shared_ptr<const std::string>& msg = sendQueue_.front();

    const std::string& msg = *(sendQueue_.front());
    logger_->trace("do_write: {} bytes", sendQueue_.size());

    ws_.async_write(
                boost::beast::net::buffer(msg),
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &PlainWebsocketSession::on_write,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2)));
}

//----------------------------------------------------------------------------

SslWebsocketSession::SslWebsocketSession(uint64_t id, boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream,
                                         const ConnectionDetail& connectionDetail) :
    WebsocketSessionImpl(id, boost::asio::make_strand(stream.get_executor())),
    ws_(std::move(stream))
{
    connectionDetail_ = connectionDetail;
    logger_->debug("SslWebsocketSession: from:{}", connectionDetail_);
}

void SslWebsocketSession::stop()
{
    do_timeout();
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


void SslWebsocketSession::start_timer()
{
    // Wait on the timer
    timer_.async_wait(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_timer,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void SslWebsocketSession::do_eof()
{
    eof_ = true;

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Perform the SSL shutdown
    ws_.next_layer().async_shutdown(
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &SslWebsocketSession::on_shutdown,
                        shared_from_this(),
                        std::placeholders::_1)));
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

void SslWebsocketSession::do_timeout()
{
    // If this is true it means we timed out performing the shutdown
    if (eof_)
        return;

    // Start the timer again
    timer_.expires_at((std::chrono::steady_clock::time_point::max)());
    on_timer({});
    do_eof();
}

void SslWebsocketSession::set_control_callback()
{
    // Set the control callback. This will be called
    // on every incoming ping, pong, and close frame.
    ws_.control_callback(
                std::bind(
                    &WebsocketSessionImpl::on_control_callback,
                    this,
                    std::placeholders::_1,
                    std::placeholders::_2));
}

bool SslWebsocketSession::is_open() const
{
    return ws_.is_open();
}

// Start the asynchronous operation
void SslWebsocketSession::do_accept(Request&& req)
{
    acceptedRequest_ = std::move(req);

    set_control_callback();
    // Set the control callback. This will be called
    // on every incoming ping, pong, and close frame.
    ws_.control_callback(
                std::bind(
                    &WebsocketSessionImpl::on_control_callback,
                    this,
                    std::placeholders::_1,
                    std::placeholders::_2));

    // Set the timer
    timer_.expires_after(std::chrono::seconds(15));

    // Accept the websocket handshake
    ws_.async_accept(
                acceptedRequest_.impl->request,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_accept,
                        shared_from_this(),
                        std::placeholders::_1)));
}

void SslWebsocketSession::do_ping()
{
    // Now send the ping
    ws_.async_ping({},
                   boost::asio::bind_executor(
                       strand_,
                       std::bind(
                           &WebsocketSessionImpl::on_ping,
                           shared_from_this(),
                           std::placeholders::_1)));
}

void SslWebsocketSession::do_read()
{
    logger_->trace("do_read");

    // Read a message into our buffer
    ws_.async_read(
                rxBuffer_,
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &WebsocketSessionImpl::on_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2)));
}

void SslWebsocketSession::do_write()
{
    logger_->trace("do_write");
    if (sendQueue_.empty())
        return;

    const std::shared_ptr<const std::string>& msg = sendQueue_.front();
    logger_->trace("do_write: {} bytes", sendQueue_.size());

    ws_.async_write(
                boost::beast::net::buffer(*msg),
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &SslWebsocketSession::on_write,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2)));
}

std::shared_ptr<PlainWebsocketSession> make_websocket_session(uint64_t id, boost::asio::ip::tcp::socket socket, Request&& req,
                                                              WebsocketConnectCb connectCb,
                                                              WebsocketReadCb readCb,
                                                              const ConnectionDetail& connectionDetail)
{
    auto session = std::make_shared<PlainWebsocketSession>(id, std::move(socket), connectionDetail);
    session->setConnectCb(connectCb);
    session->setReadCb(readCb);
    session->run(std::move(req));
    return session;
}

std::shared_ptr<SslWebsocketSession> make_websocket_session(uint64_t id, boost::beast::ssl_stream<boost::asio::ip::tcp::socket> stream, Request&& req,
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
