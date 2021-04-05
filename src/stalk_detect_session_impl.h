#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include "stalk_types_internal.h"
#include "stalk_web_session.h"

namespace Stalk
{

// Detects SSL handshakes
class DetectSession : public std::enable_shared_from_this<DetectSession>
{
public:

    DetectSession(
            boost::asio::ip::tcp::socket&& socket,
            boost::asio::ssl::context& ctx) :
        stream_(std::move(socket)),
        ctx_(ctx),
        logger_(Logger::get("WebServer.DetectSession"))
    {
        logger_->trace("DetectSession()");
    }

    ~DetectSession()
    {
        logger_->trace("~DetectSession()");
    }

    DetectSession& setWebsocketPreUpgradeCb(WebsocketPreUpgradeCb cb)
    {
        websocketPreUpgradeCb_ = cb;
        return *this;
    }

    DetectSession& setWebsocketConnectCb(WebsocketConnectCb cb)
    {
        websocketConnectCb_ = cb;
        return *this;
    }

    DetectSession& setWebsocketReadCb(WebsocketReadCb cb)
    {
        websocketReadCb_ = cb;
        return *this;
    }

    DetectSession& setHttpReqCb(HttpRequestCb cb)
    {
        httpRequestCb_ = cb;
        return *this;
    }

    // Launch the detector
    void run()
    {
        async_detect_ssl(
                    stream_,
                    buffer_,
                    boost::beast::bind_front_handler(
                        &DetectSession::on_detect,
                        this->shared_from_this()));
    }

    void on_detect(boost::system::error_code ec, bool result)
    {
        if (ec)
        {
            logger_->error("on_detect: {}", ec.message());
            return;
        }

        static std::atomic<uint64_t> nextId = 1;

        uint64_t id = nextId++;

        logger_->trace("on_detect: {}", (result ? "ssl" : "tcp"));
        std::shared_ptr<HttpSession> session;
        if (result)
            session = std::make_shared<SslHttpSession>(id, std::move(stream_), ctx_, std::move(buffer_));
        else
            session = std::make_shared<PlainHttpSession>(id, std::move(stream_), std::move(buffer_));

        session->setWebsocketPreUpgradeCb(websocketPreUpgradeCb_);
        session->setWebsocketConnectCb(websocketConnectCb_);
        session->setWebsocketReadCb(websocketReadCb_);
        session->setHttpReqCb(httpRequestCb_);

        session->run();
    }

private:
    boost::beast::tcp_stream stream_;
    boost::asio::ssl::context& ctx_;
    boost::beast::flat_buffer buffer_;
    WebsocketPreUpgradeCb websocketPreUpgradeCb_;
    WebsocketConnectCb websocketConnectCb_;
    WebsocketReadCb websocketReadCb_;
    HttpRequestCb httpRequestCb_;
    LogPtr logger_;
};


} // namespace Stalk
