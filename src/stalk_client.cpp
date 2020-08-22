#include "stalk/stalk_client.h"
#include <variant>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include "stalk/stalk_types.h"
#include "stalk/stalk_request.h"
#include "stalk/stalk_response.h"
#include "stalk_request_impl.h"
#include "stalk_response_impl.h"
#include "stalk_verb_convert.h"
#include "stalk_field_convert.h"
#include "utils/string_transform.h"
#include "logger.h"


namespace Stalk
{

// Performs an HTTP GET and prints the response
class ClientSsl : public std::enable_shared_from_this<ClientSsl>
{
public:

    ClientSsl(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx) :
        resolver_(ioc),
        stream_(ioc, ctx),
        logger_(Logger::get(("ClientSsl.") + std::to_string(reinterpret_cast<uint64_t>(this))))
    {
        logger_->trace("ClientSsl()");
    }

    ~ClientSsl()
    {
        logger_->trace("~ClientSsl()");
    }

    // Start the asynchronous operation
    void run(const std::string& host, const std::string& port, Request&& req,
             WebClient::ResponseCb&& responseCb, WebClient::ErrorCb&& errorCb)
    {
        logger_->debug("run: host:{} port:{}", host, port);

        req_ = std::move(req);
        // clear info from previous run
        resp_ = Response();

        responseCb_ = std::move(responseCb);
        errorCb_ = std::move(errorCb);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(!SSL_set_tlsext_host_name(stream_.native_handle(), host.c_str()))
        {
            boost::system::error_code ec { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            logger_->error("run: SSL_set_tlsext_host_name failed: {}", ec.message());
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
                        &ClientSsl::on_resolve,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));
    }

    void stop()
    {
        logger_->debug("stop()");
        boost::system::error_code ec;
#warning "TODO ; SSL Client stop()"
#if 0
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
#endif
    }

private:

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

        // Make the connection on the IP address we get from a lookup
        boost::asio::async_connect(
                    stream_.next_layer(),
                    results.begin(),
                    results.end(),
                    std::bind(
                        &ClientSsl::on_connect,
                        shared_from_this(),
                        std::placeholders::_1));
    }

    void on_connect(boost::system::error_code ec)
    {
        logger_->trace("on_connect: {}", ec.message());

        if (ec)
        {
            logger_->error("on_connect: {}", ec.message());
            return fail(ec, "connect");
        }

        // Perform the SSL handshake
        stream_.async_handshake(
                    boost::asio::ssl::stream_base::client,
                    std::bind(
                        &ClientSsl::on_handshake,
                        shared_from_this(),
                        std::placeholders::_1));
    }

    void on_handshake(boost::system::error_code ec)
    {
        logger_->trace("on_handshake: {}", ec.message());

        if (ec)
        {
            logger_->error("on_handshake: {}", ec.message());
            return fail(ec, "handshake");
        }

        // Send the HTTP request to the remote host
        boost::beast::http::async_write(stream_, req_.impl->request,
                          std::bind(
                              &ClientSsl::on_write,
                              shared_from_this(),
                              std::placeholders::_1,
                              std::placeholders::_2));
    }

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        logger_->trace("on_write: ec:{} bytes:{}", ec.message(), bytes_transferred);

        if (ec)
        {
            logger_->error("on_write: {}", ec.message());
            return fail(ec, "write");
        }

        // Receive the HTTP response
        boost::beast::http::async_read(stream_, buffer_, resp_.impl->response,
                                       std::bind(
                                           &ClientSsl::on_read,
                                           shared_from_this(),
                                           std::placeholders::_1,
                                           std::placeholders::_2));

    }

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        logger_->trace("on_read: ec:{} bytes:{}", ec.message(), bytes_transferred);

        if (ec)
        {
            logger_->error("on_read: {}", ec.message());
            return fail(ec, "read");
        }

#if 1
        /// \todo Keep open if 1.1 ?
        // Gracefully close the stream
        stream_.async_shutdown(
                    std::bind(
                        &ClientSsl::on_shutdown,
                        shared_from_this(),
                        std::placeholders::_1));
#endif
        if (responseCb_)
            responseCb_(std::move(resp_));
    }

    void on_shutdown(boost::system::error_code ec)
    {
        logger_->trace("on_shutdown: {}", ec.message());
#if 0
        if (ec == boost::asio::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }
#endif

        boost::system::error_code ignoredEc;
        stream_.lowest_layer().cancel(ignoredEc);
        stream_.lowest_layer().close(ignoredEc);

        if (ec && ec != boost::asio::error::eof)
        {
            logger_->error("on_shutdown: {}", ec.message());
            return fail(ec, "shutdown");
        }

        // If we get here then the connection is closed gracefully
    }


    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    boost::beast::flat_buffer buffer_;
    WebClient::ResponseCb responseCb_;
    WebClient::ErrorCb errorCb_;
    Request req_;
    Response resp_;
    std::shared_ptr<spdlog::logger> logger_;
};

// Performs an HTTP GET and prints the response
class ClientTcp : public std::enable_shared_from_this<ClientTcp>
{
public:

    ClientTcp(boost::asio::io_context& ioc) :
        resolver_(ioc),
        socket_(ioc),
        logger_(Logger::get(("ClientTcp.") + std::to_string(reinterpret_cast<uint64_t>(this))))
    {
        logger_->trace("ClientTcp()");
    }

    ~ClientTcp()
    {
        logger_->trace("~ClientTcp()");
    }

    // Start the asynchronous operation
    bool run(const std::string& host, const std::string& port, Request&& req,
             WebClient::ResponseCb&& responseCb, WebClient::ErrorCb&& errorCb)
    {
        logger_->debug("run: host:{} port:{}", host, port);

        if (inProgress_)
            return false;

        inProgress_ = true;

        req_ = std::move(req);
        // clear info from previous run
        resp_ = Response();

        responseCb_ = std::move(responseCb);
        errorCb_ = std::move(errorCb);

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
                        &ClientTcp::on_resolve,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));

        return true;
    }

    void stop()
    {
        logger_->debug("stop()");
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

private:

    void fail(boost::system::error_code ec, char const* what)
    {
        inProgress_ = false;
        connected_ = false;

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

        // Make the connection on the IP address we get from a lookup
        boost::asio::async_connect(
                    socket_,
                    results.begin(),
                    results.end(),
                    std::bind(
                        &ClientTcp::on_connect,
                        shared_from_this(),
                        std::placeholders::_1));
    }

    void on_connect(boost::system::error_code ec)
    {
        logger_->trace("on_connect: {}", ec.message());

        if (ec)
        {
            logger_->error("on_connect: {}", ec.message());
            return fail(ec, "connect");
        }

        connected_ = true;
        // Send the HTTP request to the remote host
        boost::beast::http::async_write(socket_, req_.impl->request,
                          std::bind(
                              &ClientTcp::on_write,
                              shared_from_this(),
                              std::placeholders::_1,
                              std::placeholders::_2));
    }

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        logger_->trace("on_write: ec:{} bytes:{}", ec.message(), bytes_transferred);

        if (ec)
        {
            logger_->error("on_write: {}", ec.message());
            return fail(ec, "write");
        }

        // Receive the HTTP response
        boost::beast::http::async_read(socket_, buffer_, resp_.impl->response,
                                       std::bind(
                                           &ClientTcp::on_read,
                                           shared_from_this(),
                                           std::placeholders::_1,
                                           std::placeholders::_2));

    }

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        logger_->trace("on_read: ec:{} bytes:{}", ec.message(), bytes_transferred);

        if (ec)
        {
            logger_->error("on_read: {}", ec.message());
            return fail(ec, "read");
        }

        if (!resp_.keepAlive())
        {
            logger_->trace("on_read: !keepAlive: closing");
            /// \todo Keep open if 1.1 ?
            // Gracefully close the stream
            boost::system::error_code ignoredEc;
            socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignoredEc);
            socket_.cancel(ignoredEc);
            socket_.close(ignoredEc);
            connected_ = false;
            inProgress_ = false;
        }

        if (responseCb_)
        {
            logger_->trace("on_read: sending response");
            responseCb_(std::move(resp_));
        }
    }

    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    boost::beast::flat_buffer buffer_;
    WebClient::ResponseCb responseCb_;
    WebClient::ErrorCb errorCb_;
    Request req_;
    Response resp_;
    bool connected_ = false;
    bool inProgress_ = false;
    std::shared_ptr<spdlog::logger> logger_;
};


//------------------------------------------------------------------------------------------------

class WebClientImpl
{
public:

    WebClientImpl(boost::asio::io_context& ioc);

    void key(const std::string& key);
    void cert(const std::string& cert);

    void run(const std::string& host, const std::string& port, bool ssl, Request&& req,
             WebClient::ResponseCb&& respCb, WebClient::ErrorCb&& errorCb);
    bool stop();

    const std::string& url() const;

    const Request& req() const;
    Request& req();

    boost::asio::ssl::context& ctx();

private:
    boost::asio::io_context& ioc_;
    boost::asio::ssl::context ctx_;
    Request req_;
    std::shared_ptr<spdlog::logger> logger_;
    std::variant<std::shared_ptr<ClientTcp>, std::shared_ptr<ClientSsl>> client_;
};


WebClientImpl::WebClientImpl(boost::asio::io_context& ioc) :
    ioc_(ioc),
    ctx_(boost::asio::ssl::context::sslv23),
    logger_(Logger::get(std::string("Stalk.WebClient.") + std::to_string(reinterpret_cast<uint64_t>(this))))
{
    ctx_.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);
}

void WebClientImpl::key(const std::string& key)
{
    logger_->trace("key: {}", key);
    ctx_.use_private_key(boost::asio::buffer(key.data(), key.size()), boost::asio::ssl::context::file_format::pem);
}

void WebClientImpl::cert(const std::string& cert)
{
    logger_->trace("cert: {}", cert);
    ctx_.use_certificate_chain(boost::asio::buffer(cert.data(), cert.size()));
}

void WebClientImpl::run(const std::string& host, const std::string& port, bool ssl,
                        Request&& req, WebClient::ResponseCb&& respCb, WebClient::ErrorCb&& errorCb)
{
    logger_->debug("run: {}:{} {}", host, port, req);

    if (ssl)
    {
        auto client = std::make_shared<ClientSsl>(ioc_, ctx_);
        client->run(host, port, std::move(req), std::move(respCb), std::move(errorCb));
        client_ = client;
    }
    else
    {
        auto client = std::make_shared<ClientTcp>(ioc_);
        client->run(host, port, std::move(req), std::move(respCb), std::move(errorCb));
        client_ = client;
    }
}

bool WebClientImpl::stop()
{
    std::visit([](auto&& arg){ arg->stop(); }, client_);
    return true;
}

const Request& WebClientImpl::req() const
{
    return req_;
}

Request& WebClientImpl::req()
{
    return req_;
}

boost::asio::ssl::context& WebClientImpl::ctx()
{
    return ctx_;
}

//----------------------------------------------------------------------------

WebClient::WebClient(boost::asio::io_context& ioc) :
    impl_(std::make_unique<WebClientImpl>(ioc))
{
}

WebClient::~WebClient()
{
}

WebClient& WebClient::key(const std::string& key)
{
    impl_->key(key);
    return *this;
}

WebClient& WebClient::cert(const std::string& cert)
{
    impl_->cert(cert);
    return *this;
}

WebClient::State WebClient::get(const std::string& host, const std::string& port, bool ssl, const std::string& path,
                    ResponseCb&& respCb, ErrorCb&& errorCb, const std::string& accept)
{
    return req(host, port, ssl, path, Verb::Get, std::string(), std::string(), std::move(respCb), std::move(errorCb), accept);
}

WebClient::State WebClient::post(const std::string& host, const std::string& port, bool ssl, const std::string& path,
                     const std::string& contentType, std::string&& body,
          ResponseCb&& respCb, ErrorCb&& errorCb,
          const std::string& accept)
{
    return req(host, port, ssl, path, Verb::Post, contentType, std::move(body), std::move(respCb), std::move(errorCb), accept);
}

WebClient::State WebClient::req(const std::string& host, const std::string& port, bool ssl, const std::string& path,
                    Verb method, const std::string& contentType, std::string&& body,
                    ResponseCb&& respCb, ErrorCb&& errorCb, const std::string& accept)
{
    Request req;
    req.target(path);
    req.method(method);
    if (!contentType.empty())
        req.set(Field::content_type, contentType);
    if (!body.empty())
        req.body(std::move(body));
    req.set(Field::accept, accept);

    return run(host, port, ssl, std::move(req), std::move(respCb), std::move(errorCb));
}

WebClient::State WebClient::run(const std::string& host, const std::string& port, bool ssl,
                    Request&& req, ResponseCb&& respCb, ErrorCb&& errorCb)
{
    impl_->run(host, port, ssl, std::move(req), std::move(respCb), std::move(errorCb));
    return State::InProgress;
}

bool WebClient::stop()
{
    return impl_->stop();
}

boost::asio::ssl::context& WebClient::ctx()
{
    return impl_->ctx();
}

} // namespace Stalk
