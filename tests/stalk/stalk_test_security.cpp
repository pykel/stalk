
#include "doctest.h"
#include <iostream>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include "stalk/stalk_request.h"
#include "stalk/stalk_server.h"
#include "stalk/stalk_client.h"
#include "web_client_types.h"
#include "web_client_ssl.h"
#include "web_client_tcp.h"
#include "logger.h"
#include "test_fixtures.h"

struct RequestInfo
{
    RequestInfo(const Stalk::ConnectionDetail& detail, Stalk::Request&& req, Stalk::RequestVariables&& variables) :
        detail(detail),
        req(std::move(req)),
        variables(std::move(variables))
    {
    }

    Stalk::ConnectionDetail detail;
    Stalk::Request req;
    Stalk::RequestVariables variables;
};

TEST_CASE("stalk-router-test") {
    std::function<void()> exitTestFn;

    Logger::setLevel(spdlog::level::warn);

    auto logger = Logger::get("stalk-router-test");
    logger->set_level(spdlog::level::info);
    logger->info("starting");

    boost::asio::io_context ioc;

    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

    auto startTestTimer = [&ioc, logger, timer](auto chronoTime) {
        timer->expires_after(chronoTime);
        timer->async_wait([&ioc, timer](const boost::system::error_code&) { ioc.stop(); });
    };

    std::map<std::string, std::vector<RequestInfo>> receivedRequests;

    const std::string addr = "::1";
    auto server = std::make_shared<Stalk::WebServer>(ioc, addr, 0);

    server->run();

    logger->info("Server running on port: {}", server->port());

    auto addRoute = [logger, &server, &receivedRequests](const std::string& id, const std::string& path, const std::set<Stalk::Verb>& methods, Stalk::Status status) {
        server->addHttpRoute(Stalk::Route::Http(
                                path,
                                methods,
                                [&, id, status, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received Req to route id:{} req:{}", id, req);

                                    auto resp = Stalk::Response::build(req, status);
                                    //receivedRequests.try_emplace(id, detail, std::move(req), std::move(variables));
                                    receivedRequests[id].emplace_back(detail, std::move(req), std::move(variables));

                                    send(std::move(resp));
                                }));
        };


    auto client = std::make_shared<Stalk::WebClient>(ioc);
    client->ctx().set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);

    Stalk::Status clientReceivedStatus = Stalk::Status::unknown;

    auto clientResponseCb = [logger, client, server, timer, &clientReceivedStatus](Stalk::Response&& resp)
        {
            logger->info("Received response: {}", resp);
            clientReceivedStatus = resp.status();
            server->stop();
            client->stop();
            boost::system::error_code ec;
            timer->cancel(ec);
        };

    auto clientErrorCb = [logger](const boost::system::error_code& ec, std::string&& msg)
        {
            logger->error("Received Error response: {} : msg:{}", ec.message(), msg);
        };

    startTestTimer(std::chrono::milliseconds(500));

    SUBCASE("Ok") {

        const std::string id = "NotFound_NoRoute";
        const auto status = Stalk::Status::ok;

        addRoute(id, "/test-route", { Stalk::Verb::Get }, status);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/test-route",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables.size(), 0);
    }

    SUBCASE("NotFound_NoRoute") {

        const std::string id = "NotFound_NoRoute";

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/test-route",
                        "application/json", "{ \"bodyKey\", \"bodyValue\" }",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::not_found);
        REQUIRE_EQ(receivedRequests.size(), 0);
    }

    SUBCASE("NotFound_NoMatchingMethod") {

        const std::string id = "NotFound_NoMatchingMethod";
        const auto status = Stalk::Status::created;

        addRoute(id, "/test-route", { Stalk::Verb::Get }, status);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/test-route",
                        "application/json", "{ \"bodyKey\", \"bodyValue\" }",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::method_not_allowed);
        REQUIRE_EQ(receivedRequests.size(), 0);
    }

    SUBCASE("OptionalPathVariableNotProvided") {

        const std::string id = "optionalPathVariableNotProvided";
        const auto status = Stalk::Status::ok;
        addRoute(id, "/test-route/:required-variable/?optional-variable", { Stalk::Verb::Get, Stalk::Verb::Post }, status);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/test-route/var1",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "required-variable", "var1" }
        });
    }

    SUBCASE("OptionalPathVariableNotProvidedTrailingSlash") {

        const std::string id = "optionalPathVariableNotProvidedTrailingSlash";
        const auto status = Stalk::Status::ok;
        addRoute(id, "/test-route/:required-variable/?optional-variable", { Stalk::Verb::Get, Stalk::Verb::Post }, status);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/test-route/var1/",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "required-variable", "var1" }
        });
    }


    SUBCASE("OptionalPathVariableProvided") {

        const std::string id = "optionalPathVariableProvided";
        const auto status = Stalk::Status::created;
        addRoute(id, "/test-route/:required-variable/?optional-variable", { Stalk::Verb::Get, Stalk::Verb::Post }, status);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/test-route/var1/var2",
                        "application/json", "{ \"bodyKey\", \"bodyValue\" }",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Post);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "required-variable", "var1" },
            { "optional-variable", "var2" }
        });
    }

    SUBCASE("OptionalPathVariableProvidedTrailingSlash") {

        const std::string id = "optionalPathVariableProvidedTrailingSlash";
        const auto status = Stalk::Status::created;
        addRoute(id, "/test-route/:required-variable/?optional-variable", { Stalk::Verb::Get, Stalk::Verb::Post }, status);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/test-route/var1/var2/",
                        "application/json", "{ \"bodyKey\", \"bodyValue\" }",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Post);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "required-variable", "var1" },
            { "optional-variable", "var2" }
        });
    }


    SUBCASE("MethodRouting_1") {

        addRoute("get", "/api/v1/users/:id", { Stalk::Verb::Get }, Stalk::Status::ok);
        addRoute("post", "/api/v1/users/:id", { Stalk::Verb::Post }, Stalk::Status::created);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/v1/users/0123456789",
                       clientResponseCb, clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::ok);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["get"].size(), 1);
    }

    SUBCASE("MethodRouting_2") {

        addRoute("get", "/api/v1/users/:id", { Stalk::Verb::Get }, Stalk::Status::ok);
        addRoute("post", "/api/v1/users/:id", { Stalk::Verb::Post }, Stalk::Status::created);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/api/v1/users/0123456789", "contentType", "body",
                     clientResponseCb, clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::created);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["post"].size(), 1);
    }

    SUBCASE("RoutePrecedence1") {

        const auto status = Stalk::Status::ok;

        addRoute("/api", "/api", { Stalk::Verb::Get }, status);
        addRoute("/api/", "/api/", { Stalk::Verb::Get }, status); // this route overrides the previous
        addRoute("api", "api", { Stalk::Verb::Get }, status);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["/api"].size(), 0);
        REQUIRE_EQ(receivedRequests["/api/"].size(), 1);
    }

    SUBCASE("RoutePrecedence2") {

        const auto status = Stalk::Status::ok;

        addRoute("/api", "/api", { Stalk::Verb::Get }, status);
        addRoute("/api/", "/api/", { Stalk::Verb::Get }, status); // this route overrides the previous
        addRoute("api", "api", { Stalk::Verb::Get }, status);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["/api"].size(), 0);
        REQUIRE_EQ(receivedRequests["/api/"].size(), 1);
    }

    SUBCASE("RoutePrecedence3") {

        addRoute("/api", "/api", { Stalk::Verb::Get }, Stalk::Status::no_content);
        addRoute("/api/v1", "/api/v1", { Stalk::Verb::Get }, Stalk::Status::ok);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/v1",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::ok);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["/api/v1"].size(), 1);
    }

    SUBCASE("RoutePrecedence4") {

        // inserted in the opposite order should not change behaviour
        addRoute("/api/v1", "/api/v1", { Stalk::Verb::Get }, Stalk::Status::ok);
        addRoute("/api", "/api", { Stalk::Verb::Get }, Stalk::Status::no_content);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/v1",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::ok);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["/api/v1"].size(), 1);
    }

    SUBCASE("RoutePrecedence5_1") {

        addRoute("user", "/api/v1/users/:id", { Stalk::Verb::Get }, Stalk::Status::ok);
        addRoute("info", "/api/v1/users/info", { Stalk::Verb::Get }, Stalk::Status::ok);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/v1/users/1234567890",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::ok);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["user"].size(), 1);

        const auto& reqInfo = receivedRequests["user"].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "id", "1234567890" }
        });
    }

    SUBCASE("RoutePrecedence5_2") {

        addRoute("user", "/api/v1/users/:id", { Stalk::Verb::Get }, Stalk::Status::ok);
        addRoute("info", "/api/v1/users/info", { Stalk::Verb::Get }, Stalk::Status::ok);

        logger->info("Running client");
        client->get(addr, std::to_string(server->port()), false, "/api/v1/users/info",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::ok);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["info"].size(), 1);

        const auto& reqInfo = receivedRequests["info"].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables.empty(), true);
    }

    SUBCASE("RoutePrecedence_Method") {

        addRoute("user", "/api/v1/users/:id", { Stalk::Verb::Post }, Stalk::Status::created);
        addRoute("info", "/api/v1/users/info", { Stalk::Verb::Get }, Stalk::Status::ok);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/api/v1/users/info", "contentType", "body",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::created);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["user"].size(), 1);

        const auto& reqInfo = receivedRequests["user"].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Post);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "id", "info" }
        });
    }


    SUBCASE("Route_Variables_1") {

        addRoute("variables", "/api/v1/users/:id/:infoType/required_path/?operationType", { Stalk::Verb::Post }, Stalk::Status::created);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/api/v1/users/userId/firstName", "contentType", "body",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::not_found);
        REQUIRE_EQ(receivedRequests.size(), 0);
    }

    SUBCASE("Route_Variables_2") {

        addRoute("variables", "/api/v1/users/:id/:infoType/required_path/?operationType", { Stalk::Verb::Post }, Stalk::Status::created);

        logger->info("Running client");
        client->post(addr, std::to_string(server->port()), false, "/api/v1/users/userId/firstName/required_path", "contentType", "body",
                       clientResponseCb,
                       clientErrorCb);

        ioc.run();

        CHECK_EQ(clientReceivedStatus, Stalk::Status::created);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests["user"].size(), 1);

        const auto& reqInfo = receivedRequests["user"].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Post);
        CHECK_EQ(reqInfo.variables, Stalk::RequestVariables {
            { "id", "userId" },
            { "infoType", "firstName" }
        });
    }


#if 0
    SUBCASE("routing-tests") {

        webServer->addHttpRoute(WebServer::Route::Http(
                                    "/test-1/:var1/operation/:var2", { boost::beast::http::verb::get },
                                    [logger, &exitTest](WebServer::Request&& req, const WebServer::RequestVariables&& requestVars, WebServer::SendResponse&& send)
                                    {
                                        logger->info("Received {}", req);

                                        const auto itVar1 = requestVars.find("var1");
                                        const bool haveVar1 = itVar1 != requestVars.end() && itVar1->second == "someusername";
                                        CHECK(haveVar1 == true);

                                        const auto itVar2 = requestVars.find("var2");
                                        const bool haveVar2 = itVar2 != requestVars.end() && itVar2->second == "newusername";
                                        CHECK(haveVar2 == true);

                                        WebServer::Response resp(boost::beast::http::status::ok, req.version());
                                        resp.set(boost::beast::http::field::server, "TestServer");
                                        resp.set(boost::beast::http::field::content_type, "text/html");
                                        resp.keep_alive(req.keep_alive());
                                        resp.body() = std::string("TestData");
                                        resp.prepare_payload();
                                        send(std::move(resp));

                                        exitTest();
                                    }));


        // Create the web client
        boost::asio::ssl::context clientCtx1(boost::asio::ssl::context::sslv23);
        clientCtx1.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);

        boost::asio::ssl::context clientCtx2(boost::asio::ssl::context::sslv23);
        clientCtx2.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);

        auto clientResponseCb = [logger](const WebServer::Response& resp)
            {
                logger->info("Received response: {}", resp);
            };

        auto clientErrorCb = [logger](const boost::system::error_code& ec, const std::string& msg)
            {
                logger->info("Received Error response: {} : msg:{}", ec.message(), msg);
            };

        auto webClient1 = std::make_shared<WebClientSsl>(ioc, clientCtx1);
        logger->info("Running client1");
        webClient1->run("::1", std::to_string(webServer->port()).c_str(), "/someTarget", boost::beast::http::verb::get, "*/*",
                       clientResponseCb,
                       clientErrorCb);

        auto webClient2 = std::make_shared<WebClientSsl>(ioc, clientCtx2);
        logger->info("Running client2");
        webClient2->run("::1", std::to_string(webServer->port()).c_str(), "/test-1/someusername/operation/newusername", boost::beast::http::verb::get, "*/*",
                       clientResponseCb,
                       clientErrorCb);


        ioc.run();
    }


    SUBCASE("delayed-response-tests") {

        static const unsigned reqCount = 10;
        static unsigned reqReceived = 0;
        unsigned respReceived = 0;
        unsigned respErrorsReceived = 0;

        webServer->addHttpRoute(WebServer::Route::Http(
                                    "/test-2", { boost::beast::http::verb::get },
                                    [&ioc, logger, &exitTest](WebServer::Request&& req, const WebServer::RequestVariables&&, WebServer::SendResponse&& send)
                                    {
                                        logger->info("Received {}", req);

                                        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

                                        // respond after timer fires
                                        timer->expires_after(std::chrono::seconds(2));
                                        timer->async_wait([timer, logger, &exitTest, req{std::move(req)}, send{std::move(send)}](const boost::system::error_code&)
                                            {
                                                logger->info("Responding to request {}", req);

                                                WebServer::Response resp(boost::beast::http::status::ok, req.version());
                                                resp.set(boost::beast::http::field::server, "TestServer");
                                                resp.set(boost::beast::http::field::content_type, "text/html");
                                                resp.keep_alive(req.keep_alive());
                                                resp.body() = std::string("TestData");
                                                resp.prepare_payload();
                                                send(std::move(resp));

                                                ++reqReceived;
                                                if (reqReceived == reqCount)
                                                    exitTest();
                                            });
                                    }));


        for (unsigned i = 0; i < reqCount; ++i)
        {
            auto client = std::make_shared<WebClientTcp>(ioc);
            client->run("::1", std::to_string(webServer->port()).c_str(), std::string("/test-2/") + std::to_string(i), boost::beast::http::verb::get, "*/*",
                        [logger, i, &respReceived](const WebServer::Response& resp)
                                    {
                                        logger->info("Client {} : Received response: {}", i, resp);
                                        ++respReceived;
                                    },
                        [logger, i, &respErrorsReceived](const boost::system::error_code& ec, const std::string& msg)
                                    {
                                        logger->info("Client {} : Received Error response: {} : msg:{}", i, ec.message(), msg);
                                        ++respErrorsReceived;
                                    });
        }

        ioc.run();

        CHECK(reqReceived == reqCount);
        CHECK(respReceived == reqCount);
    }

    SUBCASE("delayed-response-closed-client-tests") {

        const unsigned reqCount = 10;
        unsigned reqReceived = 0;
        unsigned respReceived = 0;
        unsigned respErrorsReceived = 0;

        webServer->addHttpRoute(WebServer::Route::Http(
                                    "/test-3", { boost::beast::http::verb::get },
                                    [&ioc, logger, &reqReceived, &exitTest](WebServer::Request&& req, const WebServer::RequestVariables&&, WebServer::SendResponse&& send)
                                    {
                                        logger->info("Received {}", req);

                                        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

                                        // respond after timer fires
                                        timer->expires_after(std::chrono::seconds(2));
                                        timer->async_wait([timer, logger, &reqReceived, &exitTest, req{std::move(req)}, send{std::move(send)}](const boost::system::error_code&)
                                            {
                                                logger->info("Responding to request {}", req);

                                                WebServer::Response resp(boost::beast::http::status::ok, req.version());
                                                resp.set(boost::beast::http::field::server, "TestServer");
                                                resp.set(boost::beast::http::field::content_type, "text/html");
                                                resp.keep_alive(req.keep_alive());
                                                resp.body() = std::string("TestData");
                                                resp.prepare_payload();
                                                send(std::move(resp));

                                                ++reqReceived;
                                                if (reqReceived == reqCount)
                                                    exitTest();
                                            });
                                    }));

        std::vector<std::shared_ptr<WebClientTcp>> clients;
        for (unsigned i = 0; i < reqCount; ++i)
        {
            auto client = std::make_shared<WebClientTcp>(ioc);
            client->run("::1", std::to_string(webServer->port()).c_str(), std::string("/test-3/") + std::to_string(i), boost::beast::http::verb::get, "*/*",
                        [logger, i, &respReceived](const WebServer::Response& resp)
                                    {
                                        logger->info("Client {} : Received response: {}", i, resp);
                                        ++respReceived;
                                    },
                        [logger, i, &respErrorsReceived](const boost::system::error_code& ec, const std::string& msg)
                                    {
                                        logger->info("Client {} : Received Error response: {} : msg:{}", i, ec.message(), msg);
                                        ++respErrorsReceived;
                                    });

            clients.push_back(client);
        }

        {
            auto timer = std::make_shared<boost::asio::steady_timer>(ioc);
            timer->expires_after(std::chrono::seconds(1));
            timer->async_wait([timer, logger, clients](const boost::system::error_code&)
            {
                logger->info("Forcing Stopping {} clients", clients.size());
                for (auto& client : clients) { client->stop(); }
            });
        }

        ioc.run();

        CHECK(reqReceived == reqCount);
        CHECK(respReceived == 0);
    }

#endif
    std::cerr << "**** Test exiting" << std::endl;
}
