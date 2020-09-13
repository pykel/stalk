
#include "doctest.h"
#include <iostream>
#include <thread>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include "stalk/stalk_request.h"
#include "stalk/stalk_server.h"
#include "stalk/stalk_client.h"
#include "stalk/stalk_logger.h"
#include "web_client_types.h"
#include "web_client_ssl.h"
#include "web_client_tcp.h"
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

TEST_CASE("stalk-thread") {
    std::function<void()> exitTestFn;

    Stalk::Logger::setDefaultLevel(Stalk::Logger::Warn);

    auto logger = Stalk::Logger::get("stalk-thread-tests");
    logger->setLevel(Stalk::Logger::Info);
    logger->info("starting");

    const int clientCount = 100;
    const int threadCount = 8;
    std::vector<std::thread> threads;
    threads.reserve(threadCount - 1);

    boost::asio::io_context ioc(threadCount);

    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

    auto startTestTimer = [&ioc, logger, timer](auto chronoTime) {
        timer->expires_after(chronoTime);
        timer->async_wait([&ioc, timer](const boost::system::error_code&) { ioc.stop(); });
    };

    std::mutex m;
    std::map<std::string, std::vector<RequestInfo>> receivedRequests;

    const std::string addr = "::1";
    auto server = std::make_shared<Stalk::WebServer>(ioc, addr, 0);

    server->run();

    logger->info("Server running on port: {}", server->port());

    auto addRoute = [&, logger](const std::string& id, const std::string& path, const std::set<Stalk::Verb>& methods, Stalk::Status status) {
        server->addHttpRoute(Stalk::Route::Http(
                                path,
                                methods,
                                [&, id, status, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received Req to route thread:{}, id:{} req:{}", std::this_thread::get_id(), id, req);

                                    auto resp = Stalk::Response::build(req, status);

                                    {
                                        std::scoped_lock lock(m);

                                        {
                                            auto it = receivedRequests.find(id);
                                            if (it == receivedRequests.end())
                                                receivedRequests[id].reserve(clientCount);
                                        }

                                        receivedRequests[id].emplace_back(detail, std::move(req), std::move(variables));
                                    }

                                    send(std::move(resp));
                                }));
        };


    std::atomic<int> responseCount = 0;
    std::map<Stalk::Status, size_t> clientReceivedStatusCounts;
    auto addStatus = [&clientReceivedStatusCounts, &m](Stalk::Status status)
        {
            std::scoped_lock lock(m);
            clientReceivedStatusCounts[status]++;
        };

    auto clientResponseCb = [&, logger, server, timer](std::shared_ptr<Stalk::WebClient> client, Stalk::Response&& resp)
        {
            responseCount++;
            logger->info("Received response thread:{}, responseCount:{}: {}", std::this_thread::get_id(), responseCount, resp);
            addStatus(resp.status());
            if (responseCount >= clientCount)
            {
                logger->info("Received required number of responses exiting");

                server->stop();
                client->stop();
                boost::system::error_code ec;
                timer->cancel(ec);
            }
        };

    auto clientErrorCb = [logger](const boost::system::error_code& ec, std::string&& msg)
        {
            logger->error("Received Error response: {} : msg:{}", ec.message(), msg);
        };

    startTestTimer(std::chrono::milliseconds(1000));

    SUBCASE("Ok") {

        const std::string id = "threads";
        const auto status = Stalk::Status::ok;

        addRoute(id, "/test-route", { Stalk::Verb::Get }, status);

        std::vector<std::shared_ptr<Stalk::WebClient>> clients;
        auto addClient = [&]() {
            auto client = std::make_shared<Stalk::WebClient>(ioc);
            client->ctx().set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);
            client->get(addr, std::to_string(server->port()), false, "/test-route",
                           [client, clientResponseCb](Stalk::Response&& resp) { clientResponseCb(client, std::move(resp)); },
                           clientErrorCb);

            clients.push_back(client);
        };

        logger->info("Launching clients");

        for (auto i = 0; i < clientCount; ++i)
        {
            addClient();
        }

        for (auto i = threadCount - 1; i > 0; --i)
        {
            threads.emplace_back([&ioc, logger] {
                logger->info("starting thread {}", std::this_thread::get_id());
                ioc.run();
                logger->info("exiting thread {}", std::this_thread::get_id());
            });
        }
        ioc.run();

        for(auto& t : threads)
        {
            t.join();
        }

        CHECK_EQ(responseCount, clientCount);
#if 0
        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables.size(), 0);
#endif
    }

    std::cerr << "**** Test exiting" << std::endl;
}


TEST_CASE("stalk-thread-delayed-response") {
    std::function<void()> exitTestFn;

    Stalk::Logger::setDefaultLevel(Stalk::Logger::Warn);

    auto logger = Stalk::Logger::get("stalk_test.stalk-thread-delayed-response");
    logger->setLevel(Stalk::Logger::Info);
    logger->info("starting");

    const int clientCount = 100;
    const int threadCount = 20;
    std::vector<std::thread> threads;
    threads.reserve(threadCount - 1);

    boost::asio::io_context ioc(threadCount);

    auto timer = std::make_shared<boost::asio::steady_timer>(ioc);

    auto startTestTimer = [&ioc, logger, timer](auto chronoTime) {
        timer->expires_after(chronoTime);
        timer->async_wait([&ioc, timer](const boost::system::error_code&) { ioc.stop(); });
    };

    std::mutex m;
    std::map<std::string, std::vector<RequestInfo>> receivedRequests;

    const std::string addr = "::1";
    auto server = std::make_shared<Stalk::WebServer>(ioc, addr, 0);

    server->run();

    logger->info("Server running on port: {}", server->port());

    auto addRoute = [&, logger](const std::string& id, const std::string& path, const std::set<Stalk::Verb>& methods, Stalk::Status status) {
        server->addHttpRoute(Stalk::Route::Http(
                                path,
                                methods,
                                [&, id, status, logger](Stalk::ConnectionDetail detail, Stalk::Request&& req, Stalk::RequestVariables&& variables, Stalk::SendResponse&& send)
                                {
                                    logger->info("Received Req to route thread:{}, id:{} req:{}", std::this_thread::get_id(), id, req);

                                    auto resp = Stalk::Response::build(req, status);

                                    {
                                        std::scoped_lock lock(m);

                                        {
                                            auto it = receivedRequests.find(id);
                                            if (it == receivedRequests.end())
                                                receivedRequests[id].reserve(clientCount);
                                        }

                                        receivedRequests[id].emplace_back(detail, std::move(req), std::move(variables));
                                    }

                                    {
                                        logger->info("Delaying response thread:{}, id:{}", std::this_thread::get_id(), id);

                                        auto timer = std::make_shared<boost::asio::steady_timer>(ioc);
                                        timer->expires_after(std::chrono::milliseconds(1000));
                                        timer->async_wait([logger, id, timer, resp = std::move(resp), send = std::move(send)](const boost::system::error_code&) mutable
                                            {
                                                logger->info("Sending Delayed response thread:{}, id:{}", std::this_thread::get_id(), id);
                                                send(std::move(resp));
                                            });

                                    }
                                }));
        };


    std::atomic<int> responseCount = 0;
    std::map<Stalk::Status, size_t> clientReceivedStatusCounts;
    auto addStatus = [&clientReceivedStatusCounts, &m](Stalk::Status status)
        {
            std::scoped_lock lock(m);
            clientReceivedStatusCounts[status]++;
        };

    auto clientResponseCb = [&, logger, server, timer](std::shared_ptr<Stalk::WebClient> client, Stalk::Response&& resp)
        {
            responseCount++;
            logger->info("Received response thread:{}, responseCount:{}: {}", std::this_thread::get_id(), responseCount, resp);
            addStatus(resp.status());
            if (responseCount >= clientCount)
            {
                logger->info("Received required number of responses exiting");

                server->stop();
                client->stop();
                boost::system::error_code ec;
                timer->cancel(ec);
            }
        };

    auto clientErrorCb = [logger](const boost::system::error_code& ec, std::string&& msg)
        {
            logger->error("Received Error response: {} : msg:{}", ec.message(), msg);
        };

    startTestTimer(std::chrono::milliseconds(2000));

    SUBCASE("Ok") {

        const std::string id = "threads-delayed-response";
        const auto status = Stalk::Status::ok;

        addRoute(id, "/test-route", { Stalk::Verb::Get }, status);

        std::vector<std::shared_ptr<Stalk::WebClient>> clients;
        auto addClient = [&]() {
            auto client = std::make_shared<Stalk::WebClient>(ioc);
            client->ctx().set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);
            client->get(addr, std::to_string(server->port()), false, "/test-route",
                           [client, clientResponseCb](Stalk::Response&& resp) { clientResponseCb(client, std::move(resp)); },
                           clientErrorCb);

            clients.push_back(client);
        };

        logger->info("Launching clients");

        for (auto i = 0; i < clientCount; ++i)
        {
            addClient();
        }

        for (auto i = threadCount - 1; i > 0; --i)
        {
            threads.emplace_back([&ioc, logger] {
                logger->info("starting thread {}", std::this_thread::get_id());
                ioc.run();
                logger->info("exiting thread {}", std::this_thread::get_id());
            });
        }
        ioc.run();

        for(auto& t : threads)
        {
            t.join();
        }

        CHECK_EQ(responseCount, clientCount);
#if 0
        CHECK_EQ(clientReceivedStatus, status);
        REQUIRE_EQ(receivedRequests.size(), 1);
        REQUIRE_EQ(receivedRequests[id].size(), 1);

        const auto& reqInfo = receivedRequests[id].front();
        CHECK_EQ(reqInfo.req.method(), Stalk::Verb::Get);
        CHECK_EQ(reqInfo.variables.size(), 0);
#endif
    }

    std::cerr << "**** Test exiting" << std::endl;
}
