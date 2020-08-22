#include "web_client_tcp.h"

#include <iostream>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>


WebClientTcp::WebClientTcp(boost::asio::io_context& ioc) :
    resolver_(ioc),
    socket_(ioc),
    logger_(Logger::get(("WebClientTcp.") + std::to_string(reinterpret_cast<uint64_t>(this))))
{
    logger_->trace("WebClientTcp()");
}

WebClientTcp::~WebClientTcp()
{
    logger_->trace("~WebClientTcp()");
}

void WebClientTcp::fail(boost::system::error_code ec, char const* what)
{
    if (errorCb_)
        errorCb_(ec, what);
}

void WebClientTcp::run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
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
                    &WebClientTcp::on_resolve,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2));
}

void WebClientTcp::run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
         const std::string& acceptType,
         WebClient::ResponseCb responseCb, WebClient::ErrorCb errorCb)
{
    return run(host, port, target, method, acceptType, "", "", responseCb, errorCb);
}

void WebClientTcp::stop()
{
    logger_->debug("stop()");
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

void WebClientTcp::on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
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
                    &WebClientTcp::on_connect,
                    shared_from_this(),
                    std::placeholders::_1));
}

void WebClientTcp::on_connect(boost::system::error_code ec)
{
    logger_->trace("on_connect: {}", ec.message());

    if (ec)
    {
        logger_->error("on_connect: {}", ec.message());
        return fail(ec, "connect");
    }

    // Send the HTTP request to the remote host
    boost::beast::http::async_write(socket_, req_,
                      std::bind(
                          &WebClientTcp::on_write,
                          shared_from_this(),
                          std::placeholders::_1,
                          std::placeholders::_2));
}

void WebClientTcp::on_write(boost::system::error_code ec, std::size_t bytes_transferred)
{
    logger_->trace("on_write: ec:{} bytes:{}", ec.message(), bytes_transferred);

    if (ec)
    {
        logger_->error("on_write: {}", ec.message());
        return fail(ec, "write");
    }

    // Receive the HTTP response
    boost::beast::http::async_read(socket_, buffer_, res_,
                                   std::bind(
                                       &WebClientTcp::on_read,
                                       shared_from_this(),
                                       std::placeholders::_1,
                                       std::placeholders::_2));
}

void WebClientTcp::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
{
    logger_->trace("on_read: ec:{} bytes:{}", ec.message(), bytes_transferred);

    if (ec)
    {
        logger_->error("on_read: {}", ec.message());
        return fail(ec, "read");
    }

    if (responseCb_)
        responseCb_(res_);

    boost::system::error_code ignoredEc;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignoredEc);
    socket_.close(ignoredEc);
}
