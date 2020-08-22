#include <iostream>
#include <string>
#include <map>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "LUrlParser/LUrlParser.h"
#include "stalk/stalk_websocket_client.h"
#include "stalk/stalk_server.h"
#include "logger.h"
#include "test_fixtures.h"


int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
        return 1;
    }

    auto logger = Logger::get("test_websocket_client");

    LUrlParser::clParseURL url = LUrlParser::clParseURL::ParseURL(std::string(argv[1]));

    boost::asio::io_context ioc;

    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", 0, serverKey(), serverCert());
    webServer->run();

    webServer->addWebsocketRoute(Stalk::Route::Websocket(
        "/websocket_route",
        [logger](bool connected, std::shared_ptr<Stalk::WebsocketSession> session, Stalk::RequestVariables&& variables) {
            logger->info("WebSocket Route Callback: Connected:{}", connected);

            session->send("Hello websocket msg from Stalk");
        },
        [logger](std::shared_ptr<Stalk::WebsocketSession> session, std::string&& msg) {
            logger->info("WebSocket Route Callback: msg:{}", msg);
        }));


    boost::asio::ssl::context ctx{boost::asio::ssl::context::sslv23_client};

    auto client = std::make_shared<Stalk::WebsocketClient>(ioc, ctx);

    bool secureSocket = url.m_Scheme == "wss";

    client->connect(
        secureSocket, "::1", std::to_string(webServer->port()),
        std::move(Stalk::Request().target("/")),
        [logger](const boost::system::error_code& ec, const Stalk::Response& resp) {
            logger->info("WebSocket client Connection CB: Status:{}, Body:{}, ec:{}", resp.status(), resp.body(), ec.message());
        },
        [logger](std::string&& msg) {
            logger->info("WebSocket client msg callback:{}", msg);
        },
        [logger](const boost::system::error_code& ec, std::string&& errMsg) {
            logger->info("WebSocket client error callback: errMsg: {}, ec:{}", errMsg, ec.message());
        });
#if 0
    client->connect(secureSocket, url.m_Host, url.m_Port, Stalk::Request(),
                    [](const boost::system::error_code& ec, const Stalk::Response& resp) {},
                    [](std::string&& msg) {},
                    [](const boost::system::error_code&, std::string&& errMsg) {});
#endif
    ioc.run();

    return 0;
}

