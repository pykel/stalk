#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include "stalk_detect_session_impl.h"

namespace Stalk
{


// Accepts incoming connections and launches the sessions
class ListenerImpl : public std::enable_shared_from_this<ListenerImpl>
{
public:

    ListenerImpl(
            boost::asio::io_context& ioc,
            boost::asio::ssl::context&& ctx,
            const std::string& address,
            uint16_t port) :
        ioc_(ioc),
        ctx_(std::move(ctx)),
        acceptor_(boost::asio::make_strand(ioc)),
        address_(address),
        port_(port),
        logger_(Logger::get("WebServer.Listener"))
    {
        logger_->trace("Listener()");
    }

    ~ListenerImpl()
    {
        logger_->trace("~Listener()");
    }

    void setSslContext(boost::asio::ssl::context&& ctx)
    {
        ctx_ = std::move(ctx);
    }

    boost::asio::ssl::context& sslContext()
    {
        return ctx_;
    }

    uint16_t port() const
    {
        return acceptor_.local_endpoint().port();
    }

    void setWsPreUpgrade(WebsocketPreUpgradeCb cb)
    {
        websocketPreUpgradeCb_ = cb;
    }

    void setWsConnect(WebsocketConnectCb cb)
    {
        websocketConnectCb_ = cb;
    }

    void setWsRead(WebsocketReadCb cb)
    {
        websocketReadCb_ = cb;
    }

    void setHttpReq(HttpRequestCb cb)
    {
        httpRequestCb_ = cb;
    }

    // Start accepting incoming connections
    void run()
    {
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(address_), port_);

        acceptor_.open(endpoint.protocol(), ec);
        if (ec)
        {
            logger_->error("open: {}", ec.message());
            return;
        }

        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
        if (ec)
        {
            logger_->error("set_option: {}", ec.message());
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            logger_->error("bind: {}", ec.message());
            return;
        }

        // Start listening for connections
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            logger_->error("listen: {}", ec.message());
            return;
        }

        if (!acceptor_.is_open())
            return;

        do_accept();
    }

    void stop()
    {
        logger_->info("stop");
        boost::system::error_code ec;
        acceptor_.cancel(ec);
        acceptor_.close(ec);
    }

private:

    void do_accept()
    {
        acceptor_.async_accept(
            boost::asio::make_strand(ioc_),
            boost::beast::bind_front_handler(
                &ListenerImpl::on_accept,
                shared_from_this()));
    }

    void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
    {
        if (ec)
        {
            if (ec.value() == boost::system::errc::operation_canceled)
                logger_->debug("accept: {}", ec.message());
            else
                logger_->error("accept: {}", ec.message());
            return;
        }

        // Create the detector http_session and run it
        auto detectSession = std::make_shared<DetectSession>(std::move(socket), ctx_);
        detectSession->setWebsocketPreUpgradeCb(websocketPreUpgradeCb_);
        detectSession->setWebsocketConnectCb(websocketConnectCb_);
        detectSession->setWebsocketReadCb(websocketReadCb_);
        detectSession->setHttpReqCb(httpRequestCb_);
        detectSession->run();

        // Accept another connection
        do_accept();
    }


    boost::asio::io_context& ioc_;
    boost::asio::ssl::context ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string address_;
    uint16_t port_;
    WebsocketPreUpgradeCb websocketPreUpgradeCb_;
    WebsocketConnectCb websocketConnectCb_;
    WebsocketReadCb websocketReadCb_;
    HttpRequestCb httpRequestCb_;
    LogPtr logger_;
};

} // namespace Stalk
