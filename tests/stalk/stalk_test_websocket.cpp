#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#include "doctest.h"
#include <iostream>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/algorithm/string.hpp>
#include "stalk/stalk_request.h"
#include "stalk/stalk_server.h"
#include "stalk/stalk_websocket_session.h"
#include "stalk/stalk_websocket_client.h"
#include "stalk/stalk_connection_detail_ostream.h"
#include "stalk/stalk_logger.h"
#include "test_fixtures.h"


TEST_CASE("stalk-websocket-test") {

    std::function<void()> exitTestFn;

    Stalk::Logger::setDefaultLevel(Stalk::Logger::Trace);

    auto logger = Stalk::Logger::get("stalk-websocket-test");
    logger->info("starting");


    enum class Counters
    {
        ServerHttpRoute,
        ServerWebsocketConnected,
        ServerWebsocketMsg,
        ClientWebsocketConnected,
        ClientWebsocketMsg,
        ClientWebsocketError,
    };

    std::map<Counters, uint64_t> counters;

    struct TestCase
    {
        TestCase(bool secure, const std::string& path, uint64_t sr, uint64_t swc, uint64_t swm, uint64_t cwc, uint64_t cwm, uint64_t cwe) :
            secure(secure),
            path(path),
            expectedCounts({
                { Counters::ServerHttpRoute, sr },
                { Counters::ServerWebsocketConnected, swc },
                { Counters::ServerWebsocketMsg, swm },
                { Counters::ClientWebsocketConnected, cwc },
                { Counters::ClientWebsocketMsg, cwm },
                { Counters::ClientWebsocketError, cwe } })
        {}
        bool secure;
        std::string path;
        std::map<Counters, uint64_t> expectedCounts;
    };

    auto validateTestCase = [&logger, &counters](const TestCase& testCase)
        {
            for (const auto& expected : testCase.expectedCounts)
            {
                logger->info("({}) expected: {} : actual {}", static_cast<int>(expected.first), expected.second, counters[expected.first]);
                CHECK(counters[expected.first] == expected.second);
            }
        };

    boost::asio::io_context ioc;

    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", 0, serverKey(), serverCert());

    std::vector<std::shared_ptr<Stalk::WebsocketSession>> sessions;

    webServer->addHttpRoute(Stalk::Route::Http(
        "/",
        { Stalk::Verb::Get, Stalk::Verb::Connect },
        [&counters, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send) {
            logger->info("HTTP Route Callback: from:{}, {}", detail, req);
            ++counters[Counters::ServerHttpRoute];
        }));

    webServer->addWebsocketRoute(Stalk::Route::Websocket(
        "/websocket_route",
        Stalk::RoutedWebsocketPreUpgradeCb(),
        [&counters, &sessions, logger](bool connected, std::shared_ptr<Stalk::WebsocketSession> session, Stalk::RequestVariables&& variables) {
            logger->info("WebSocket Route Callback: Connected:{}", connected);
            if (connected)
            {
                sessions.push_back(session);
                session->send("Hello websocket msg from Stalk");
                ++counters[Counters::ServerWebsocketConnected];
            }
        },
        [&counters, logger](std::shared_ptr<Stalk::WebsocketSession> session, std::string&& msg) {
            logger->info("WebSocket Route Callback: msg:{}", msg);
            ++counters[Counters::ServerWebsocketMsg];
        }));

    boost::asio::ssl::context clientCtx { boost::asio::ssl::context::tlsv12 };
    auto createClient = [&ioc, &clientCtx, &webServer, &logger, &counters](bool secure, const std::string& path) -> std::shared_ptr<Stalk::WebsocketClient>
        {
            auto client = std::make_shared<Stalk::WebsocketClient>(ioc, clientCtx);
            client->key(clientKey())
                   .cert(clientCert());

            client->connect(
                secure, "::1", std::to_string(webServer->port()),
                std::move(Stalk::Request().target(path)),
                [&counters, logger, client](const boost::system::error_code& ec, const Stalk::Response& resp) {
                    logger->info("WebSocket client Connection CB: Status:{}, Body:{}, ec:{}, peer:{}",
                                 resp.status(), resp.body(), ec.message(), client->peerConnectionDetail());
                    ++counters[Counters::ClientWebsocketConnected];
                },
                [&counters, logger, client](std::string&& msg) {
                    logger->info("WebSocket client msg callback:{}", msg);
                    ++counters[Counters::ClientWebsocketMsg];
                    client->send("Hello websocket msg from Stalk");
                },
                [&counters, logger, webServer](const boost::system::error_code& ec, std::string&& errMsg) {
                    logger->info("WebSocket client error callback: errMsg: {}, ec:{}", errMsg, ec.message());
                    ++counters[Counters::ClientWebsocketError];
                });

            return client;
        };

    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

    timer->expires_after(std::chrono::milliseconds(100));
    timer->async_wait([&ioc, &sessions, &webServer, timer, logger](const boost::system::error_code& ec)
        {
            if (!ec)
            {
                logger->info("Stopping");
                //ioc.stop();

                for (auto& session : sessions)
                {
                    session->close();
                }

                webServer->stop();
            }
        });


    SUBCASE("stalk-websocket-test.websocket_tcp_no_route") {

        // Start the web server
        webServer->run();
        TestCase testCase { false, "/", 0, 0, 0, 0, 0, 1 };
        auto client = createClient(testCase.secure, testCase.path);

        ioc.run();

        validateTestCase(testCase);
    }

    SUBCASE("stalk-websocket-test.websocket_ssl_no_route") {

        // Start the web server
        webServer->run();
        TestCase testCase { true, "/", 0, 0, 0, 0, 0, 1 };
        auto client = createClient(testCase.secure, testCase.path);

        ioc.run();

        validateTestCase(testCase);
    }

    SUBCASE("stalk-websocket-test.websocket_tcp_route") {

        // Start the web server
        webServer->run();
        TestCase testCase { false, "/websocket_route", 0, 1, 1, 1, 1, 1 };
        auto client = createClient(testCase.secure, testCase.path);

        ioc.run();

        validateTestCase(testCase);
    }

    SUBCASE("stalk-websocket-test.websocket_ssl_route") {

        // Start the web server
        webServer->run();
        TestCase testCase { true, "/websocket_route", 0, 1, 1, 1, 1, 1 };
        auto client = createClient(testCase.secure, testCase.path);

        ioc.run();

        validateTestCase(testCase);
    }

#if 0
    // old test cases
    SUBCASE("routing-tests") {
    SUBCASE("delayed-response-tests") {
    SUBCASE("delayed-response-closed-client-tests") {
#endif
    std::cerr << "**** Test exiting" << std::endl;
}

TEST_CASE("stalk-websocket-security-test") {

    std::function<void()> exitTestFn;

    Stalk::Logger::setDefaultLevel(Stalk::Logger::Info);

    auto logger = Stalk::Logger::get("stalk-websocket-test");
    logger->info("starting");

    Stalk::ConnectionDetail testClientConnectionDetail;

    boost::asio::io_context ioc;

    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", 9990, serverKey(), serverCert());

    webServer->addHttpRoute(Stalk::Route::Http(
        "/",
        { Stalk::Verb::Get, Stalk::Verb::Connect },
        [logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send) {
            logger->info("HTTP Route Callback: from:{}, {}", detail, req);
        }));

    webServer->addWebsocketRoute(Stalk::Route::Websocket(
        "/websocket_route",
        Stalk::RoutedWebsocketPreUpgradeCb(),
        [logger, &testClientConnectionDetail](bool connected, std::shared_ptr<Stalk::WebsocketSession> session, Stalk::RequestVariables&& variables) {
            logger->info("WebSocket Route Callback: Connected:{} : connectionDetail:{}", connected, session->connectionDetail());
            testClientConnectionDetail = session->connectionDetail();
            session->send("Hello websocket msg from Stalk");
        },
        [logger](std::shared_ptr<Stalk::WebsocketSession> session, std::string&& msg) {
            logger->info("WebSocket Route Callback: msg:{}", msg);
        }));

    boost::asio::ssl::context clientCtx { boost::asio::ssl::context::tlsv12 };
    auto createClient = [&ioc, &clientCtx, &webServer, &logger](bool secure, const std::string& path) -> std::shared_ptr<Stalk::WebsocketClient>
        {
            clientCtx.set_verify_mode(boost::asio::ssl::verify_peer);// | boost::asio::ssl::verify_fail_if_no_peer_cert);
            auto client = std::make_shared<Stalk::WebsocketClient>(ioc, clientCtx);
            client->key(clientKey())
                   .cert(clientCert());

            client->connect(
                secure, "::1", std::to_string(webServer->port()),
                std::move(Stalk::Request().target(path)),
                [logger, client](const boost::system::error_code& ec, const Stalk::Response& resp) {
                    logger->info("WebSocket client Connection CB: Status:{}, Body:{}, ec:{}, peer:{}",
                                 resp.status(), resp.body(), ec.message(), client->peerConnectionDetail());
                },
                [logger, client](std::string&& msg) {
                    logger->info("WebSocket client msg callback:{}", msg);
                    client->send("Hello websocket msg from Stalk");
                },
                [logger, webServer](const boost::system::error_code& ec, std::string&& errMsg) {
                    logger->info("WebSocket client error callback: errMsg: {}, ec:{}", errMsg, ec.message());
                });

            return client;
        };

    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

    timer->expires_after(std::chrono::milliseconds(100));
    timer->async_wait([&ioc, timer, logger](const boost::system::error_code& ec)
        {
            if (!ec)
            {
                logger->info("Stopping IOC");
                ioc.stop();
            }
        });

    SUBCASE("stalk-websocket-security-test.websocket_ssl_client_credentials") {

        // Start the web server
        webServer->run();

        auto client = createClient(true, "websocket_route");

        ioc.run();

        CHECK(testClientConnectionDetail.encrypted == true);

        auto trim = [](const std::string& str) -> std::string
            {
                return boost::algorithm::trim_right_copy(boost::algorithm::trim_left_copy(str));
            };
        auto a = trim(testClientConnectionDetail.security.peerCert.pem);
        auto b = trim(clientCert());
        CHECK(a == b);
    }

    std::cerr << "**** Test exiting" << std::endl;
}


TEST_CASE("stalk-websocket-performance-test") {

    std::function<void()> exitTestFn;

    Stalk::Logger::setDefaultLevel(Stalk::Logger::Info);

    auto logger = Stalk::Logger::get("stalk-websocket-performance-test");
    logger->info("starting");

    enum class Counters
    {
        ServerHttpRoute,
        ServerWebsocketConnected,
        ServerWebsocketMsg,
        ClientWebsocketConnected,
        ClientWebsocketMsg,
        ClientWebsocketError,
    };

    const std::map<Counters, const char*> counterNames = {
        { Counters::ServerHttpRoute, "ServerHttpRoute" },
        { Counters::ServerWebsocketConnected, "ServerWebsocketConnected" },
        { Counters::ServerWebsocketMsg, "ServerWebsocketMsg" },
        { Counters::ClientWebsocketConnected, "ClientWebsocketConnected" },
        { Counters::ClientWebsocketMsg, "ClientWebsocketMsg" },
        { Counters::ClientWebsocketError, "ClientWebsocketError" }
    };

    auto counterName = [&counterNames](const Counters& c) -> const char*
        {
            static const char* unknown = "Unknown";
            auto it = counterNames.find(c);
            return it == counterNames.end() ? unknown : it->second;
        };

    std::map<Counters, uint64_t> counters;

    boost::asio::io_context ioc;

    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", 0, serverKey(), serverCert());

    webServer->addHttpRoute(Stalk::Route::Http(
        "/",
        { Stalk::Verb::Get, Stalk::Verb::Connect },
        [&counters, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send) {
            logger->debug("HTTP Route Callback: from:{}, {}", detail, req);
            ++counters[Counters::ServerHttpRoute];
        }));

    webServer->addWebsocketRoute(Stalk::Route::Websocket(
        "/websocket_route",
        Stalk::RoutedWebsocketPreUpgradeCb(),
        [&counters, logger](bool connected, std::shared_ptr<Stalk::WebsocketSession> session, Stalk::RequestVariables&& variables) {
            if (connected)
            {
                logger->debug("WebSocket Route Callback: Connected:{}", connected);
                //session->send("Hello websocket msg from Stalk Server");
                ++counters[Counters::ServerWebsocketConnected];
            }
            else
            {
                logger->info("WebSocket Route Callback: Disconnected:({})", connected);
            }
        },
        [&counters, logger](std::shared_ptr<Stalk::WebsocketSession> session, std::string&& msg) {
            logger->debug("WebSocket Route Callback: msg:{}", msg);
            session->send("Hello websocket msg from Stalk Server");
            ++counters[Counters::ServerWebsocketMsg];
        }));


    const int msgBatchSize = 10;

    boost::asio::ssl::context clientCtx { boost::asio::ssl::context::tlsv12 };
    auto createClient = [&ioc, &clientCtx, &webServer, &logger, &counters](bool secure, const std::string& path) -> std::shared_ptr<Stalk::WebsocketClient>
        {
            auto client = std::make_shared<Stalk::WebsocketClient>(ioc, clientCtx);
            client->key(clientKey())
                   .cert(clientCert());

            client->connect(
                secure, "::1", std::to_string(webServer->port()),
                std::move(Stalk::Request().target(path)),
                [&counters, logger, client](const boost::system::error_code& ec, const Stalk::Response& resp) {
                    logger->info("WebSocket client Connection CB: Status:{}, Body:{}, ec:{}, peer:{}",
                                 resp.status(), resp.body(), ec.message(), client->peerConnectionDetail());
                    ++counters[Counters::ClientWebsocketConnected];

                    for (int i = 0; i < msgBatchSize ; ++i)
                    {
                        client->send("Hello websocket msg from Stalk Client");
                    }
                },
                [&counters, logger, client](std::string&& msg) {
                    logger->debug("WebSocket client msg callback:{}", msg);
                    ++counters[Counters::ClientWebsocketMsg];
                    client->send("Hello websocket msg from Stalk Client");
                },
                [&counters, logger, webServer](const boost::system::error_code& ec, std::string&& errMsg) {
                    logger->info("WebSocket client error callback: errMsg: {}, ec:{}", errMsg, ec.message());
                    ++counters[Counters::ClientWebsocketError];
                });

            return client;
        };

    std::vector<std::shared_ptr<Stalk::WebsocketClient>> clients;

    auto timerClients = std::make_shared<boost::asio::steady_timer>(ioc);
    timerClients->expires_after(std::chrono::milliseconds(10000));
    timerClients->async_wait([&ioc, &clients, timerClients, logger](const boost::system::error_code& ec)
        {
            if (!ec)
            {
                logger->info("Stopping Clients");
                for (auto& client : clients)
                {
                    client->stop();
                }

                clients.clear();
            }
        });

    auto timerIoc = std::make_shared<boost::asio::steady_timer>(ioc);
    timerIoc->expires_after(std::chrono::milliseconds(11000));
    timerIoc->async_wait([&ioc, &webServer, timerIoc, logger](const boost::system::error_code& ec)
        {
            if (!ec)
            {
                logger->info("Stopping Server");
                //ioc.stop();
                webServer->stop();
            }
        });

    const unsigned clientCount = 10;

    SUBCASE("stalk-websocket-test.websocket_tcp_route") {

        // Start the web server
        webServer->run();

        for (unsigned i = 0; i < clientCount; ++i)
        {
            clients.push_back(createClient(false, "/websocket_route"));
        }

        ioc.run();

        for (const auto& counter : counters)
        {
            logger->info("({}) {} : {}", static_cast<unsigned>(counter.first), counterName(counter.first), counter.second);
        }
    }

    std::cerr << "**** Test exiting" << std::endl;
}
