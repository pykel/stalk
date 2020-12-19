#include "stalk/stalk_server.h"
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/version.hpp>
#include "stalk_types_internal.h"
#include "stalk/stalk_types.h"
#include "stalk/stalk_request.h"
#include "stalk/stalk_response.h"
#include "stalk/stalk_websocket_session.h"
#include "stalk/stalk_router.h"
#include "stalk_request_impl.h"
#include "stalk_response_impl.h"
#include "stalk_web_session.h"
#include "stalk_websocket_session_impl.h"
#include "stalk_verb_convert.h"
#include "stalk_field_convert.h"
#include "stalk_connection_detail_builder.h"
#include "stalk/stalk_logger.h"


namespace Stalk
{

// Detects SSL handshakes
class DetectSession : public std::enable_shared_from_this<DetectSession>
{
public:
    DetectSession(boost::asio::ip::tcp::socket&& socket, boost::asio::ssl::context& ctx);
    ~DetectSession();

    DetectSession& setWebsocketPreUpgradeCb(WebsocketPreUpgradeCb cb);
    DetectSession& setWebsocketConnectCb(WebsocketConnectCb cb);
    DetectSession& setWebsocketReadCb(WebsocketReadCb cb);
    DetectSession& setHttpReqCb(HttpRequestCb cb);

    // Launch the detector
    void run();
    void on_detect(boost::system::error_code ec, bool result);

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

DetectSession::DetectSession(
        boost::asio::ip::tcp::socket&& socket,
        boost::asio::ssl::context& ctx) :
    stream_(std::move(socket)),
    ctx_(ctx),
    logger_(Logger::get("WebServer.DetectSession"))
{
    logger_->trace("DetectSession()");
}

DetectSession::~DetectSession()
{
    logger_->trace("~DetectSession()");
}

DetectSession& DetectSession::setWebsocketPreUpgradeCb(WebsocketPreUpgradeCb cb)
{
    websocketPreUpgradeCb_ = cb;
    return *this;
}

DetectSession& DetectSession::setWebsocketConnectCb(WebsocketConnectCb cb)
{
    websocketConnectCb_ = cb;
    return *this;
}

DetectSession& DetectSession::setWebsocketReadCb(WebsocketReadCb cb)
{
    websocketReadCb_ = cb;
    return *this;
}

DetectSession& DetectSession::setHttpReqCb(HttpRequestCb cb)
{
    httpRequestCb_ = cb;
    return *this;
}

void DetectSession::run()
{
    async_detect_ssl(
                stream_,
                buffer_,
                boost::beast::bind_front_handler(
                    &DetectSession::on_detect,
                    this->shared_from_this()));
}

void DetectSession::on_detect(boost::system::error_code ec, bool result)
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


// Accepts incoming connections and launches the sessions
class ListenerImpl : public std::enable_shared_from_this<ListenerImpl>
{
public:

    ListenerImpl(
        boost::asio::io_context& ioc,
        boost::asio::ssl::context& ctx,
        const std::string& address,
        uint16_t port);

    ~ListenerImpl();

    void setWsPreUpgrade(WebsocketPreUpgradeCb cb);
    void setWsConnect(WebsocketConnectCb cb);
    void setWsRead(WebsocketReadCb cb);
    void setHttpReq(HttpRequestCb cb);

    // Start accepting incoming connections
    void run();
    void stop();

    uint16_t port() const;

private:
    void do_accept();
    void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

    boost::asio::io_context& ioc_;
    boost::asio::ssl::context& ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string address_;
    uint16_t port_;
    WebsocketPreUpgradeCb websocketPreUpgradeCb_;
    WebsocketConnectCb websocketConnectCb_;
    WebsocketReadCb websocketReadCb_;
    HttpRequestCb httpRequestCb_;
    LogPtr logger_;
};


ListenerImpl::ListenerImpl(
        boost::asio::io_context& ioc,
        boost::asio::ssl::context& ctx,
        const std::string& address,
        uint16_t port) :
    ioc_(ioc),
    ctx_(ctx),
    acceptor_(boost::asio::make_strand(ioc)),
    address_(address),
    port_(port),
    logger_(Logger::get("WebServer.Listener"))
{
    logger_->trace("Listener()");
}

ListenerImpl::~ListenerImpl()
{
    logger_->trace("~Listener()");
}

uint16_t ListenerImpl::port() const
{
    return acceptor_.local_endpoint().port();
}

void ListenerImpl::setWsPreUpgrade(WebsocketPreUpgradeCb cb)
{
    websocketPreUpgradeCb_ = cb;
}

void ListenerImpl::setWsConnect(WebsocketConnectCb cb)
{
    websocketConnectCb_ = cb;
}

void ListenerImpl::setWsRead(WebsocketReadCb cb)
{
    websocketReadCb_ = cb;
}

void ListenerImpl::setHttpReq(HttpRequestCb cb)
{
    httpRequestCb_ = cb;
}

// Start accepting incoming connections
void ListenerImpl::run()
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

void ListenerImpl::stop()
{
    logger_->info("stop");
    boost::system::error_code ec;
    acceptor_.cancel(ec);
    acceptor_.close(ec);
}

void ListenerImpl::do_accept()
{
    acceptor_.async_accept(
        boost::asio::make_strand(ioc_),
        boost::beast::bind_front_handler(
            &ListenerImpl::on_accept,
            shared_from_this()));
}

void ListenerImpl::on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
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



// Accept incoming connections and launch the sessions.
class WebServerImpl : public std::enable_shared_from_this<WebServerImpl>
{
public:

    WebServerImpl(boost::asio::io_context& ioc,
           const std::string& address,
           uint16_t port,
           const std::string& privateKey,
           const std::string& certificate);

    void run();
    void stop();
    uint16_t port() const;

    void addHttpRoute(Route::Http&& route);
    void removeHttpRoute(const std::string& path);
    void addWebsocketRoute(Route::Websocket&& route);
    void removeWebsocketRoute(const std::string& path);
    void setRouteErrorHandler(UnroutedRequestCb cb);

private:

    void wsConnectCb(bool connected, const Request& req, SendMsg&& send);
    void httpReqCb(std::unique_ptr<Request> req, SendResponse&& send);

    boost::asio::ssl::context ctx_;
    std::shared_ptr<ListenerImpl> listener_;
    Router router_;
    UnroutedRequestCb unroutedRequestCb_;
    LogPtr logger_;
};


WebServerImpl::WebServerImpl(boost::asio::io_context& ioc,
               const std::string& address,
               uint16_t port,
               const std::string& privateKey,
               const std::string& certificate) :
    ctx_(boost::asio::ssl::context::sslv23),
    logger_(Logger::get("Stalk.WebServer"))
{
    ctx_.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);
    ctx_.set_verify_mode(boost::asio::ssl::verify_peer);// | boost::asio::ssl::verify_fail_if_no_peer_cert);
    ctx_.set_verify_callback([this](bool /*preverified*/, boost::asio::ssl::verify_context& /*ctx*/)
        {
            logger_->trace("WebServerImpl().verify_callback called");
            return true;
        });

    if (!certificate.empty())
        ctx_.use_certificate_chain(boost::asio::buffer(certificate.data(), certificate.size()));
    if (!privateKey.empty())
        ctx_.use_private_key(boost::asio::buffer(privateKey.data(), privateKey.size()), boost::asio::ssl::context::file_format::pem);

    listener_ = std::make_shared<ListenerImpl>(ioc, ctx_, address, port);

    listener_->setWsPreUpgrade([this](ConnectionDetail detail, Request&& req, SendResponse&& send, WebsocketUpgrade&& upgrade)
        {
            logger_->debug("WebsocketPreUpgradeCb {}", req);

            BeastRequest& beastRequest = req.impl->request;
            auto matchingRoute = router_.getWebsocketRoute(beastRequest.target().to_string());
            if (!matchingRoute)
            {
                logger_->debug("WebsocketPreUpgradeCb : No matching route found");
                if (unroutedRequestCb_)
                {
                    return unroutedRequestCb_(Status::not_found, detail, std::move(req), std::move(send));
                }

                return send(Response::build(req, Status::not_found));
            }

            if (matchingRoute->first.preUpgradeCb())
            {
                matchingRoute->first.preUpgradeCb()(detail, std::move(req), std::move((*matchingRoute).second), std::move(send), std::move(upgrade));
            }
            else
            {
                upgrade(std::move(req));
            }
        });

    listener_->setWsConnect([this](std::shared_ptr<WebsocketSessionImpl> session, bool connected)
        {
            logger_->debug("WebsocketConnectCb {}, {}", connected ? "true" : "false", session->request());

            BeastRequest& beastRequest = session->request().impl->request;

            auto matchingRoute = router_.getWebsocketRoute(beastRequest.target().to_string());
            if (!matchingRoute)// || !(*matchingRoute).first.connectCb())
            {
                logger_->debug("WebsocketConnectCb : No matching route found");
                return;// session->stop();
            }

            auto stalkWebsocketSession = std::make_shared<WebsocketSession>(session);
            auto readCb = matchingRoute->first.readCb();

            if (connected)
            {
                session->setReadCb([this, readCb, stalkWebsocketSession](std::shared_ptr<WebsocketSessionImpl> session, std::string&& msg)
                    {
                        logger_->debug("WebsocketReadCb msg:{}, originating http req:{}", msg, session->request());
                        if (readCb)
                            readCb(stalkWebsocketSession, std::move(msg));
                    });
            }

            const RoutedWebsocketConnectCb& cb = (*matchingRoute).first.connectCb();
            if (cb)
            {
                cb(connected, stalkWebsocketSession, std::move((*matchingRoute).second));
            }
        });

    listener_->setHttpReq([this](ConnectionDetail detail, Request&& req, SendResponse&& send)
        {
            const auto target = req.targetStr();
            logger_->debug("httpReqCb: {} : {}", target, req);

            const Verb verb = req.method();

            auto result = router_.getHttpRoute(target, verb);
            if (std::holds_alternative<Status>(result))
            {
                const auto& status = std::get<Status>(result);

                logger_->debug("Route lookup error, status:{}", status);

                if (unroutedRequestCb_)
                {
                    return unroutedRequestCb_(status, detail, std::move(req), std::move(send));
                }

                return send(Response::build(req, status));
            }

            auto& matchingRoute = std::get<Router::MatchedHttpRoute>(result);
            if (!matchingRoute.first.requestCb())
            {
                logger_->debug("Route without callback found");
                if (unroutedRequestCb_)
                {
                    return unroutedRequestCb_(Status::method_not_allowed, detail, std::move(req), std::move(send));
                }

                return send(Response::build(req, Status::method_not_allowed));
            }

            logger_->trace("Found route");
            const Route::Http& route = matchingRoute.first;

            try
            {
                route.requestCb()(detail, std::move(req), std::move(matchingRoute.second), std::move(send));
            }
            catch (const std::exception& e)
            {
                logger_->error("Caught exception handling HTTP request: {}", e.what());
            }
        });
}

void WebServerImpl::run()
{
    logger_->info("run");
    listener_->run();
}

void WebServerImpl::stop()
{
    logger_->info("stop");
    listener_->stop();
}

uint16_t WebServerImpl::port() const
{
    return listener_->port();
}

void WebServerImpl::addHttpRoute(Route::Http&& route) { return router_.addHttpRoute(std::move(route)); }
void WebServerImpl::addWebsocketRoute(Route::Websocket&& route) { return router_.addWebsocketRoute(std::move(route)); }
void WebServerImpl::removeHttpRoute(const std::string& path) { return router_.removeHttpRoute(path); }
void WebServerImpl::removeWebsocketRoute(const std::string& path) { return router_.removeWebsocketRoute(path); }
void WebServerImpl::setRouteErrorHandler(UnroutedRequestCb cb) { unroutedRequestCb_ = cb; }

//----------------------------------------------------------------------------

WebServer::WebServer(boost::asio::io_context& ioc,
       const std::string& address,
       uint16_t port,
       const std::string& privateKey,
       const std::string& certificate) :
    impl_(std::make_unique<WebServerImpl>(ioc, address, port, privateKey, certificate))
{
}

WebServer::~WebServer()
{
}

void WebServer::run()
{
    impl_->run();
}

void WebServer::stop()
{
    impl_->stop();
}

uint16_t WebServer::port() const
{
    return impl_->port();
}

void WebServer::addHttpRoute(Route::Http&& route)
{
    impl_->addHttpRoute(std::move(route));
}

void WebServer::removeHttpRoute(const std::string& path)
{
    impl_->removeHttpRoute(path);
}

void WebServer::addWebsocketRoute(Route::Websocket&& route)
{
    impl_->addWebsocketRoute(std::move(route));
}

void WebServer::removeWebsocketRoute(const std::string& path)
{
    impl_->removeWebsocketRoute(path);
}

void WebServer::setRouteErrorHandler(UnroutedRequestCb cb)
{
    impl_->setRouteErrorHandler(cb);
}

} // namespace Stalk
