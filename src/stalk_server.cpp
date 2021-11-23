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
#include "stalk_logger.h"
#include "stalk_listener_impl.h"
//#include "stalk/stalk_connection_detail_fmt.h"
#include "utils/crypto_utils.h"
//#include "stalk/stalk_connection_detail_ostream.h"


namespace Stalk
{


// Accept incoming connections and launch the sessions.
class WebServerImpl : public std::enable_shared_from_this<WebServerImpl>
{
public:

    WebServerImpl(boost::asio::io_context& ioc,
           const std::string& address,
           uint16_t port,
           const std::string& privateKey,
           const std::string& certificate,
           VerifyCallbackFn verifyCallbackFn);

    void setSslContext(boost::asio::ssl::context&& ctx)
    {
        ctx.set_verify_callback(std::bind(&WebServerImpl::verifyCb, this, std::placeholders::_1, std::placeholders::_2));

        if (!certificate_.empty())
            ctx.use_certificate_chain(boost::asio::buffer(certificate_.data(), certificate_.size()));
        if (!privateKey_.empty())
            ctx.use_private_key(boost::asio::buffer(privateKey_.data(), privateKey_.size()), boost::asio::ssl::context::file_format::pem);

        configureSslContext(ctx);

        listener_->setSslContext(std::move(ctx));
    }

    boost::asio::ssl::context& ctx() { return listener_->sslContext(); }

    void run();
    void stop();
    uint16_t port() const;

    void addHttpRoute(Route::Http&& route);
    void removeHttpRoute(const std::string& path);
    void addWebsocketRoute(Route::Websocket&& route);
    void removeWebsocketRoute(const std::string& path);
    void setRouteErrorHandler(UnroutedRequestCb cb);
    void setVerifyCallbackFn(VerifyCallbackFn verifyCallbackFn);

private:

    void wsConnectCb(bool connected, const Request& req, SendMsg&& send);
    void httpReqCb(std::unique_ptr<Request> req, SendResponse&& send);
    bool verifyCb(bool preverified, boost::asio::ssl::verify_context& ctx);

    void configureSslContext(boost::asio::ssl::context& ctx)
    {
        ctx.set_verify_callback(std::bind(&WebServerImpl::verifyCb, this, std::placeholders::_1, std::placeholders::_2));

        if (!certificate_.empty())
            ctx.use_certificate_chain(boost::asio::buffer(certificate_.data(), certificate_.size()));
        if (!privateKey_.empty())
            ctx.use_private_key(boost::asio::buffer(privateKey_.data(), privateKey_.size()), boost::asio::ssl::context::file_format::pem);
    }

//    boost::asio::ssl::context ctx_;
    std::shared_ptr<ListenerImpl> listener_;
    Router router_;
    UnroutedRequestCb unroutedRequestCb_;
    std::string privateKey_;
    std::string certificate_;
    VerifyCallbackFn verifyCallbackFn_;
    LogPtr logger_;
};


WebServerImpl::WebServerImpl(boost::asio::io_context& ioc,
               const std::string& address,
               uint16_t port,
               const std::string& privateKey,
               const std::string& certificate,
               VerifyCallbackFn verifyCallbackFn) :
    privateKey_(privateKey),
    certificate_(certificate),
    verifyCallbackFn_(verifyCallbackFn),
    logger_(Logger::get("Stalk.WebServer"))
{
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);// | boost::asio::ssl::verify_fail_if_no_peer_cert);
    configureSslContext(ctx);

    listener_ = std::make_shared<ListenerImpl>(ioc, std::move(ctx), address, port);

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

bool WebServerImpl::verifyCb(bool preverified, boost::asio::ssl::verify_context& ctx)
{
    if (!verifyCallbackFn_)
    {
        logger_->trace("verify_callback: no verifyCallbackFn assigned, returning true");
        return true;
    }

    X509_STORE_CTX* storeCtx = ctx.native_handle();
    STACK_OF(X509)* stackOfX509Validated = X509_STORE_CTX_get0_chain(storeCtx);
    STACK_OF(X509)* stackOfX509Untrusted = X509_STORE_CTX_get0_untrusted(storeCtx);
    X509* peer = X509_STORE_CTX_get_current_cert(storeCtx);

    const auto buildCert = [](const X509* cert) -> ConnectionDetail::Security::Cert
        {
            return {
                     CryptoUtils::digest(cert, "sha256"),
                     CryptoUtils::commonName(cert),
                     CryptoUtils::issuer(cert),
                     CryptoUtils::certAsPEM(cert)
                    };
        };

    const auto buildStack = [&buildCert](STACK_OF(X509)* stack) -> std::vector<ConnectionDetail::Security::Cert>
        {
            std::vector<ConnectionDetail::Security::Cert> certs;
            if (!stack)
                return certs;

            for (int idx = 0; idx < sk_X509_num(stack); ++idx)
            {
                const X509* cert = sk_X509_value(stack, idx);
                if (cert)
                {
                    certs.push_back(buildCert(cert));
                }
            }

            return certs;
        };

    auto peerCert = peer ? buildCert(peer) : ConnectionDetail::Security::Cert();
    auto validated = buildStack(stackOfX509Validated);
    auto untrusted = buildStack(stackOfX509Untrusted);
    return verifyCallbackFn_(preverified, std::move(peerCert), std::move(validated), std::move(untrusted));
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
void WebServerImpl::setVerifyCallbackFn(VerifyCallbackFn verifyCallbackFn) { verifyCallbackFn_ = verifyCallbackFn; }

//----------------------------------------------------------------------------

WebServer::WebServer(boost::asio::io_context& ioc,
       const std::string& address,
       uint16_t port,
       const std::string& privateKey,
       const std::string& certificate,
       VerifyCallbackFn verifyCallbackFn) :
    impl_(std::make_unique<WebServerImpl>(ioc, address, port, privateKey, certificate, verifyCallbackFn))
{
}

WebServer::~WebServer()
{
}

WebServer& WebServer::setSslContext(boost::asio::ssl::context&& ctx)
{
    impl_->setSslContext(std::move(ctx));
    return *this;
}

boost::asio::ssl::context& WebServer::sslContext()
{
    return impl_->ctx();
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

WebServer& WebServer::setRouteErrorHandler(UnroutedRequestCb cb)
{
    impl_->setRouteErrorHandler(cb);
    return *this;
}

WebServer& WebServer::setVerifyCallbackFn(VerifyCallbackFn verifyCallbackFn)
{
    impl_->setVerifyCallbackFn(verifyCallbackFn);
    return *this;
}


} // namespace Stalk
