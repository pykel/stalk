#include "stalk/stalk_websocket_client.h"
#include <deque>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include "stalk/stalk_types.h"
#include "stalk/stalk_request.h"
#include "stalk/stalk_response.h"
#include "stalk_request_impl.h"
#include "stalk_response_impl.h"
#include "stalk_verb_convert.h"
#include "stalk_field_convert.h"
#include "stalk_connection_detail_builder.h"
#include "stalk/stalk_logger.h"


namespace Stalk
{

// Performs an HTTP GET and prints the response
class WebsocketClientImpl : public std::enable_shared_from_this<WebsocketClientImpl>
{
public:

    WebsocketClientImpl(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx) :
        ioc_(ioc),
        ctx_(ctx),
        resolver_(ioc),
        ws_(boost::asio::make_strand(ioc)),
        logger_(Logger::get(("WebsocketClientImpl.") + std::to_string(reinterpret_cast<uint64_t>(this))))
    {
        logger_->trace("WebsocketClientImpl()");
    }

    ~WebsocketClientImpl()
    {
        logger_->trace("~WebsocketClientImpl()");
    }

    void key(const std::string& key)
    {
        logger_->trace("key: {}", key);
        key_ = key;
        ctx_.use_private_key(boost::asio::buffer(key_.data(), key_.size()), boost::asio::ssl::context::file_format::pem);
    }

    void cert(const std::string& cert)
    {
        logger_->trace("cert: {}", cert);
        cert_ = cert;
        boost::system::error_code ec;
        //ctx_.use_certificate(boost::asio::buffer(cert_.data(), cert_.size()), boost::asio::ssl::context::file_format::pem, ec);
        ctx_.use_certificate_chain(boost::asio::buffer(cert_.data(), cert_.size()), ec);
        /// \todo check ec
    }

    const ConnectionDetail& peerConnectionDetail() const
    {
        return peerConnectionDetail_;
    }

    // Start the asynchronous operation
    void connect(bool secureSocket, const std::string& host, const std::string& port, Request&& req,
           WebsocketClient::ConnectCb&& connectCb, WebsocketClient::ReceiveMsgCb&& receiveMsgCb, WebsocketClient::ErrorCb&& errorCb)
    {
        wss_ = std::make_unique<boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>>(boost::asio::make_strand(ioc_), ctx_);
        wss_->next_layer().set_verify_callback([this](bool preverified, boost::asio::ssl::verify_context& ctx)
            {
                logger_->trace("WebsocketClientImpl().verify_callback called");
                /// \todo allow verify callback with ConnectionDetail
                return true;
            });

        tls_ = secureSocket;
        host_ = host;
        port_ = port;

        connectCb_ = connectCb;
        receiveMsgCb_ = receiveMsgCb;
        errorCb_ = errorCb;

        req_ = std::move(req);
        // clear info from previous run
        resp_ = Response();

        logger_->debug("connect: useTls:{} host:{} port:{}", secureSocket, host, port);

        if (tls_)
        {
            if (!prepareSsl())
                return;
        }

        if (!req_.body().empty())
        {
            req_.set(Field::content_length, std::to_string(req_.body().size()));
        }

        if (!req_.has(Field::host))
        {
            req_.set(Field::host, host);
        }

        // Look up the domain name
        resolver_.async_resolve(host, port,
                    std::bind(
                        &WebsocketClientImpl::on_resolve,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));
    }

    bool send(const std::string& msg)
    {
        logger_->trace("send: msg.size:{}", msg.size());
        // post message via executor ready for sending
        auto msgPtr = std::make_shared<const std::string>(msg);

        if (tls_)
        {
            boost::beast::net::post(
                wss_->get_executor(),
                boost::beast::bind_front_handler(
                    &WebsocketClientImpl::on_send,
                    shared_from_this(),
                    msgPtr));
        }
        else
        {
            boost::beast::net::post(
                ws_.get_executor(),
                boost::beast::bind_front_handler(
                    &WebsocketClientImpl::on_send,
                    shared_from_this(),
                    msgPtr));
        }
        return true;
    }

    void on_send(std::shared_ptr<const std::string> msg)
    {
        sendQueue_.push_back(msg);

        // Already sending?
        if (sendQueue_.size() > 1)
            return;

        do_write();
    }

    const Response& connectResponse() const
    {
        return  resp_;
    }

    bool stop()
    {
        logger_->debug("stop()");
        boost::system::error_code ec;
        on_shutdown(boost::system::error_code());
#warning "TODO ; SSL Client stop()"
#if 0
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
#endif
        return true;
    }

private:

    void do_write()
    {
        logger_->trace("do_write");
        if (sendQueue_.empty())
            return;

        const std::shared_ptr<const std::string>& msg = sendQueue_.front();
        logger_->trace("do_write: {} bytes", sendQueue_.size());

        if (tls_)
        {
            wss_->async_write(
                        boost::beast::net::buffer(*msg),
                            std::bind(
                                &WebsocketClientImpl::on_write,
                                shared_from_this(),
                                std::placeholders::_1,
                                std::placeholders::_2));
        }
        else
        {
            ws_.async_write(
                        boost::beast::net::buffer(*msg),
                            std::bind(
                                &WebsocketClientImpl::on_write,
                                shared_from_this(),
                                std::placeholders::_1,
                                std::placeholders::_2));

        }
    }

    bool prepareSsl()
    {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(!SSL_set_tlsext_host_name(wss_->next_layer().native_handle(), host_.c_str()))
        {
            boost::system::error_code ec { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            logger_->error("run: SSL_set_tlsext_host_name failed: {}", ec.message());
            return false;
        }

        return true;
    }

    bool writeInProgress() const { return writeInProgress_; }
    void writeInProgress(bool inProgress) { writeInProgress_ = inProgress; }

    void fail(boost::system::error_code ec, char const* what)
    {
        if (errorCb_)
            errorCb_(ec, what);
    }

    void on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
    {
        logger_->trace("on_resolve: {}", ec.message());

        if (ec)
        {
            logger_->error("on_resolve: {}", ec.message());
            return fail(ec, "resolve");
        }

        if (tls_)
        {
            // Make the connection on the IP address we get from a lookup
            boost::asio::async_connect(
                        wss_->next_layer().next_layer(),
                        results.begin(),
                        results.end(),
                        std::bind(
                            &WebsocketClientImpl::on_connect,
                            shared_from_this(),
                            std::placeholders::_1));

        }
        else
        {
            // Make the connection on the IP address we get from a lookup
            boost::asio::async_connect(
                        ws_.next_layer(),
                        results.begin(),
                        results.end(),
                        std::bind(
                            &WebsocketClientImpl::on_connect,
                            shared_from_this(),
                            std::placeholders::_1));
        }
    }

    void on_connect(boost::system::error_code ec)
    {
        logger_->trace("on_connect: {}", ec.message());

        if (ec)
        {
            logger_->error("on_connect: {}", ec.message());
            return fail(ec, "connect");
        }

        if (tls_)
        {
            // Perform the SSL handshake
            wss_->next_layer().async_handshake(
                        boost::asio::ssl::stream_base::client,
                        std::bind(
                            &WebsocketClientImpl::on_ssl_handshake,
                            shared_from_this(),
                            std::placeholders::_1));
        }
        else
        {
            on_ssl_handshake(boost::system::error_code());
        }
    }

    void on_ssl_handshake(boost::system::error_code ec)
    {
        logger_->trace("on_ssl_handshake: {}", ec.message());

        if (ec)
        {
            logger_->error("on_ssl_handshake: {}", ec.message());
            return fail(ec, "ssl_handshake");
        }

        // Perform the websocket handshake
        if (tls_)
        {
            wss_->async_handshake(wsHandshakeRawResponse_, req_.get(Field::host), req_.targetStr(),
                std::bind(
                    &WebsocketClientImpl::on_handshake,
                    shared_from_this(),
                    std::placeholders::_1));

            peerConnectionDetail_ = ConnectionDetailBuilder::build(0, wss_->next_layer());
        }
        else
        {
            ws_.async_handshake(wsHandshakeRawResponse_, req_.get(Field::host), req_.targetStr(),
                std::bind(
                    &WebsocketClientImpl::on_handshake,
                    shared_from_this(),
                    std::placeholders::_1));

            peerConnectionDetail_ = ConnectionDetailBuilder::build(0, ws_.next_layer());
        }
    }

    void on_handshake(const boost::system::error_code& ec)
    {
        logger_->trace("on_handshake: {}", ec.message());

        if (ec)
        {
            logger_->error("on_handshake: {}", ec.message());
            return fail(ec, "handshake");
        }

        resp_ = Response();
        for (const auto& field : wsHandshakeRawResponse_)
        {
            resp_.set(fieldFromBeast(field.name()), std::string(field.value().begin(), field.value().end()));
        }
        resp_.status(static_cast<unsigned>(wsHandshakeRawResponse_.result_int()));

        if (connectCb_)
            connectCb_(ec, resp_);

        start_read();
    }

    void start_read()
    {
        if (tls_)
        {
            // Read a message into our buffer
            wss_->async_read(
                buffer_,
                std::bind(
                    &WebsocketClientImpl::on_read,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2));
        }
        else
        {
            // Read a message into our buffer
            ws_.async_read(
                buffer_,
                std::bind(
                    &WebsocketClientImpl::on_read,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2));
        }
    }

    void on_write(const boost::system::error_code& ec, std::size_t bytes_transferred)
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

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        logger_->trace("on_read: ec:{} bytes:{}", ec.message(), bytes_transferred);

        if (ec)
        {
            logger_->error("on_read: {}", ec.message());
            return fail(ec, "read");
        }

        auto str = boost::beast::buffers_to_string(buffer_.cdata());
        buffer_.consume(bytes_transferred);

        if (receiveMsgCb_)
            receiveMsgCb_(std::move(str));

        start_read();
    }

    void on_shutdown(boost::system::error_code ec)
    {
        logger_->trace("on_shutdown: {}", ec.message());

        if (tls_)
            shutdown_ssl();
        else
            shutdown();

        if (ec && ec != boost::asio::error::eof)
        {
            logger_->error("on_shutdown: {}", ec.message());
            return fail(ec, "shutdown");
        }
#if 0
        if (ec == boost::asio::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }
#endif
        // If we get here then the connection is closed gracefully
    }

    void shutdown_ssl()
    {
        boost::system::error_code ignoredEc;
        wss_->next_layer().next_layer().lowest_layer().cancel(ignoredEc);
        wss_->next_layer().next_layer().lowest_layer().close(ignoredEc);
    }

    void shutdown()
    {
        boost::system::error_code ignoredEc;
        ws_.next_layer().lowest_layer().cancel(ignoredEc);
        ws_.next_layer().lowest_layer().close(ignoredEc);
    }

    boost::asio::io_context& ioc_;
    boost::asio::ssl::context& ctx_;
    std::string key_;
    std::string cert_;
    bool tls_ = false;
    std::string host_;
    std::string port_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws_;
    std::unique_ptr<boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>> wss_;
    boost::beast::websocket::response_type wsHandshakeRawResponse_;
    Response resp_;
    boost::beast::flat_buffer buffer_;
    boost::beast::multi_buffer txBuffer_;
    std::deque<std::shared_ptr<const std::string>> sendQueue_;
    WebsocketClient::ConnectCb connectCb_;
    WebsocketClient::ReceiveMsgCb receiveMsgCb_;
    WebsocketClient::ErrorCb errorCb_;
    Request req_;
    ConnectionDetail peerConnectionDetail_;
    std::atomic<bool> writeInProgress_ = false;
    LogPtr logger_;
};

//----------------------------------------------------------------------------

WebsocketClient::WebsocketClient(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx) :
    impl_(std::make_unique<WebsocketClientImpl>(ioc, ctx))
{
}

WebsocketClient::~WebsocketClient()
{
}

WebsocketClient& WebsocketClient::key(const std::string& key)
{
    impl_->key(key);
    return *this;
}

WebsocketClient& WebsocketClient::cert(const std::string& cert)
{
    impl_->cert(cert);
    return *this;
}

void WebsocketClient::connect(bool secureSocket, const std::string& host, const std::string& port, Request&& req, ConnectCb&& connectCb, ReceiveMsgCb&& receiveMsgCb, ErrorCb&& errorCb)
{
    impl_->connect(secureSocket, host, port, std::move(req), std::move(connectCb), std::move(receiveMsgCb), std::move(errorCb));
}

bool WebsocketClient::send(const std::string& msg)
{
    return impl_->send(msg);
}

const Response& WebsocketClient::connectResponse() const
{
    return impl_->connectResponse();
}

const ConnectionDetail& WebsocketClient::peerConnectionDetail() const
{
    return impl_->peerConnectionDetail();
}

bool WebsocketClient::stop()
{
    return impl_->stop();
}

} // namespace Stalk
