#pragma once

#include <string>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <boost/asio/version.hpp>
#if BOOST_ASIO_VERSION >= 101800
#include <boost/asio/bind_executor.hpp>
#endif
#include <boost/asio/strand.hpp>
#include <boost/beast/http.hpp>
#include "stalk/stalk_types.h"

#if BOOST_ASIO_VERSION < 101400
using executor_context = boost::asio::io_context;
using Strand = boost::asio::strand<executor_context::executor_type>;
#elif BOOST_ASIO_VERSION < 101800
using executor_context =  boost::asio::executor;
using Strand = boost::asio::strand<executor_context>;
#else
using executor_context =  boost::asio::io_context::executor_type;
using Strand = boost::asio::strand<executor_context>;
#endif


namespace Stalk
{

class WebsocketSessionImpl;

using BeastResponse = boost::beast::http::message<false, boost::beast::http::string_body, boost::beast::http::fields>;
using BeastRequest = boost::beast::http::request<boost::beast::http::string_body>;

inline std::ostream& operator<<(std::ostream& os, const BeastRequest& request)
{
    os << request.target().to_string() << " : " << request.method() << " ";
    for (const auto& hdr : request)
    {
        os << hdr.name_string() << ":[" << hdr.value() << "] ";
    }
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const BeastResponse& response)
{
    os << response.result() << " : body:" << response.body().size() << " bytes";
    return os;
}

using HttpRequestCb = std::function<void(ConnectionDetail, Request&& req, SendResponse&& send)>;
using WebsocketPreUpgradeCb = std::function<void(ConnectionDetail, Request&&, SendResponse&& send, WebsocketUpgrade&& upgrade)>;
using WebsocketConnectCb = std::function<void(std::shared_ptr<WebsocketSessionImpl> session, bool connected)>;
using WebsocketReadCb = std::function<void(std::shared_ptr<WebsocketSessionImpl> session, std::string&& msg)>;

} // namespace Stalk
