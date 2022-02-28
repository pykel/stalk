# stalk library
C++ Boost.Beast web-service wrapper library.
Adding routing / security handling.
Websocket routing.

# Basic Usage

The following basic example creates a web-server/service, adding a route with path variables.

Taken from the `examples/stalk_routing` example.

```cpp
    auto logger = Logger::get("stalk-routing-example");

    boost::asio::io_context ioc;

    const uint16_t port = 0; // 0 -> OS assigned port number
    auto webServer = std::make_shared<Stalk::WebServer>(ioc, "::1", port, serverKey(), serverCert());

    webServer->run();

    logger->info("Web Server running on port: {}", webServer->port()); // log the OS assigned port number

    webServer->addHttpRoute(
        Stalk::Route::Http(
            "/group/:id/?optionalParam",
            { Stalk::Verb::Get, Stalk::Verb::Post },
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

    // run the ASIO event loop
    ioc.run();
```

Responses can be deferred by moving the `send` function object. This can be useful when waiting for other async operations, eg. DB lookups or transactional batched DB writes, or waiting on async web-client operations.
The example includes a simple timer based deferred response.

# Building
```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ../
# or building with tests/examples
cmake -DSTALK__ENABLE_TESTS=ON -DSTALK__ENABLE_EXAMPLES=ON \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ../

make -j$(nproc)
make install
```

# Tests
There are several test cases that validate routing, route variables, multi-threading, deferred response handling.

