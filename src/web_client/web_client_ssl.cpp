#include "web_client_ssl.h"

#include <iostream>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>


WebClientSsl::WebClientSsl(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx) :
    resolver_(ioc),
    stream_(ioc, ctx),
    logger_(Logger::get(("WebClientSsl.") + std::to_string(reinterpret_cast<uint64_t>(this))))
{
    logger_->trace("WebClientSsl()");
}

WebClientSsl::~WebClientSsl()
{
    logger_->trace("~WebClientSsl()");
}

void WebClientSsl::fail(boost::system::error_code ec, char const* what)
{
    if (errorCb_)
        errorCb_(ec, what);
}

void WebClientSsl::run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
         const std::string& accept,
         const std::string& contentType,
         const std::string& body,
         WebClient::ResponseCb responseCb, WebClient::ErrorCb errorCb)
{
    logger_->debug("run: host:{} port:{} target:{} method:{} accept:{} contentType:{} body.size:{}",
                   host, port, target, boost::beast::http::to_string(method), accept, contentType, body.size());

    // clear info from previous run
    req_ = WebClient::Request();
    res_ = WebClient::Response();

    responseCb_ = responseCb;
    errorCb_ = errorCb;
    const int version = 11; // HTTP "1.1"

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if(!SSL_set_tlsext_host_name(stream_.native_handle(), host.c_str()))
    {
        boost::system::error_code ec { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
        logger_->error("run: SSL_set_tlsext_host_name failed: {}", ec.message());
        return;
    }

    req_.version(version);
    req_.method(method);
    req_.target(target);
    req_.set(boost::beast::http::field::accept, accept);
    if (!body.empty())
    {
        req_.body() = body;
        req_.set(boost::beast::http::field::content_type, contentType);
        req_.set(boost::beast::http::field::content_length, body.size());
    }
    req_.set(boost::beast::http::field::host, host);
    req_.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver_.async_resolve(host, port,
                std::bind(
                    &WebClientSsl::on_resolve,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2));
}

void WebClientSsl::run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
         const std::string& acceptType,
         WebClient::ResponseCb responseCb, WebClient::ErrorCb errorCb)
{
    return run(host, port, target, method, acceptType, "", "", responseCb, errorCb);
}

void WebClientSsl::stop()
{
    logger_->debug("stop()");
    boost::system::error_code ec;
#warning "TODO ; SSL Client stop()"
#if 0
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
#endif
}

void WebClientSsl::on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
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
                    &WebClientSsl::on_connect,
                    shared_from_this(),
                    std::placeholders::_1));
}

void WebClientSsl::on_connect(boost::system::error_code ec)
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
                    &WebClientSsl::on_handshake,
                    shared_from_this(),
                    std::placeholders::_1));
}

void WebClientSsl::on_handshake(boost::system::error_code ec)
{
    logger_->trace("on_handshake: {}", ec.message());

    if (ec)
    {
        logger_->error("on_handshake: {}", ec.message());
        return fail(ec, "handshake");
    }

    // Send the HTTP request to the remote host
    boost::beast::http::async_write(stream_, req_,
                      std::bind(
                          &WebClientSsl::on_write,
                          shared_from_this(),
                          std::placeholders::_1,
                          std::placeholders::_2));
}

void WebClientSsl::on_write(boost::system::error_code ec, std::size_t bytes_transferred)
{
    logger_->trace("on_write: ec:{} bytes:{}", ec.message(), bytes_transferred);

    if (ec)
    {
        logger_->error("on_write: {}", ec.message());
        return fail(ec, "write");
    }

    // Receive the HTTP response
    boost::beast::http::async_read(stream_, buffer_, res_,
                                   std::bind(
                                       &WebClientSsl::on_read,
                                       shared_from_this(),
                                       std::placeholders::_1,
                                       std::placeholders::_2));
}

void WebClientSsl::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
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
                    &WebClientSsl::on_shutdown,
                    shared_from_this(),
                    std::placeholders::_1));
#endif
    if (responseCb_)
        responseCb_(res_);
}

void WebClientSsl::on_shutdown(boost::system::error_code ec)
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

