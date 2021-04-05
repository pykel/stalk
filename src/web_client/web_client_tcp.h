#pragma once

#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "web_client_types.h"
#include "stalk/stalk_logger.h"


class WebClientTcp : public std::enable_shared_from_this<WebClientTcp>
{
public:

    explicit WebClientTcp(boost::asio::io_context& ioc);
    ~WebClientTcp();

    // Start the asynchronous operation
    void run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
             const std::string& accept,
             const std::string& contentType,
             const std::string& body,
             WebClient::ResponseCb responseCb, WebClient::ErrorCb errorCb);
    void run(const std::string& host, const std::string& port, const std::string& target, boost::beast::http::verb method,
             const std::string& acceptType,
             WebClient::ResponseCb responseCb, WebClient::ErrorCb errorCb);

    void stop();

private:

    void fail(boost::system::error_code ec, char const* what);
    void on_resolve(boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
    void on_connect(boost::system::error_code ec);
    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);
    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    boost::beast::flat_buffer buffer_;
    WebClient::Request req_;
    WebClient::Response res_;
    WebClient::ResponseCb responseCb_;
    WebClient::ErrorCb errorCb_;
    Stalk::LogPtr logger_;
};
