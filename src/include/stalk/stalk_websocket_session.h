#pragma once

#include <string>
#include <memory>
#include <functional>
#include "stalk_types.h"
#include "stalk_connection_detail.h"

namespace Stalk
{

struct WebsocketSessionImpl;

struct Request;

struct WebsocketSession: public std::enable_shared_from_this<WebsocketSession>
{
    WebsocketSession(std::shared_ptr<WebsocketSessionImpl> session);

    ~WebsocketSession();

    WebsocketSession(WebsocketSession&& other);
    WebsocketSession& operator=(WebsocketSession&& other);

    uint64_t id() const;

    void send(const std::string& msg);
    void close(const std::string& reason = "");

    const ConnectionDetail& connectionDetail() const;
    const Request& request() const;
    Request& request();

    std::shared_ptr<WebsocketSessionImpl> impl;

private:
    WebsocketSession(const WebsocketSession& other) = delete;
    WebsocketSession& operator=(const WebsocketSession& other) = delete;
};

std::ostream& operator<<(std::ostream&, const WebsocketSession&);

} // namespace Stalk
