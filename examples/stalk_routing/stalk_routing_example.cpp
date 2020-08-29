
#include "stalk_routing_example.h"
#include <stdint.h>
#include <string>
#include <boost/asio/steady_timer.hpp>
#include "stalk/stalk_server.h"
#include "logger.h"

std::ostream& operator<<(std::ostream& os, const Stalk::RequestVariables& vars);


int main(int argc, char* argv[])
{
    uint16_t port = argc > 1 ? static_cast<uint16_t>(std::stoul(argv[1])) : 10000;

    Logger::setLevel(spdlog::level::trace);

    auto logger = Logger::get("stalk-routing-example");

    boost::asio::io_context ioc;

    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", port, serverKey(), serverCert());

    // Start the web server
    webServer->run();

    logger->info("Web Server running on port: {}", webServer->port());

    webServer->addHttpRoute(Stalk::Route::Http(
                                "/user/:id", { Stalk::Verb::Get },
                                [logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& requestVars, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received request: {} {} vars:{}", req.target(), req.method(), requestVars);

                                    auto resp = Stalk::Response(req)
                                                    .status(Stalk::Status::ok)
                                                    .set(Stalk::Field::content_type, "text/plain")
                                                    .body(std::string("Responding to request for user:") + requestVars["id"]);

                                    logger->info("Sending response: {} body-size:{}", resp.status(), resp.body().size());

                                    send(std::move(resp));
                                }));

    webServer->addHttpRoute(Stalk::Route::Http(
                                "/group/:id/?optionalParam", { Stalk::Verb::Get },
                                [logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& requestVars, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received request: {} {} vars:{}", req.target(), req.method(), requestVars);

                                    auto resp = Stalk::Response(req)
                                                    .status(Stalk::Status::ok)
                                                    .set(Stalk::Field::content_type, "text/plain")
                                                    .body(std::string("Responding to request for group:") + requestVars["id"]);

                                    logger->info("Sending response: {} body-size:{}", resp.status(), resp.body().size());

                                    send(std::move(resp));
                                }));

    webServer->addHttpRoute(Stalk::Route::Http(
                                "/delayed", { Stalk::Verb::Get },
                                [&ioc, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& requestVars, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received request: {} {} vars:{}", req.target(), req.method(), requestVars);
                                    logger->info("Delaying response");

                                        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

                                        // respond after timer fires
                                        timer->expires_after(std::chrono::seconds(2));
                                        timer->async_wait([timer, logger, req{std::move(req)}, send{std::move(send)}](const boost::system::error_code&)
                                            {
                                                logger->info("Responding to request {}", req);

                                                auto resp = Stalk::Response(req)
                                                                .status(Stalk::Status::ok)
                                                                .set(Stalk::Field::content_type, "text/plain")
                                                                .body("Delayed Response");

                                                send(std::move(resp));
                                            });
                                }));

    webServer->addWebsocketRoute(Stalk::Route::Websocket(
                                "/user/:id",
                                Stalk::RoutedWebsocketPreUpgradeCb(),
                                [logger](bool connected, std::shared_ptr<Stalk::WebsocketSession> session, const Stalk::RequestVariables& requestVars)
                                {
                                    logger->info("Websocket connected: {} : {} vars:{}", connected, session->request().target(), requestVars);
                                },
                                [logger](std::shared_ptr<Stalk::WebsocketSession> session, std::string&& msg)
                                {
                                    logger->info("Received msg: {} from session: {}", session->request(), msg);
                                }));

    ioc.run();

    logger->info("exiting");

    return 0;
}

std::ostream& operator<<(std::ostream& os, const Stalk::RequestVariables& vars)
{
    bool have = false;
    os << "[ ";
    for (const auto& p : vars)
    {
        if (have)
            os << ", ";
        os << p.first << ":" << p.second;
        have = true;
    }
    os << " ]";
    return os;
}
