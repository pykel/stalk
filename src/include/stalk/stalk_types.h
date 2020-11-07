#ifndef stalk_types_INCLUDED
#define stalk_types_INCLUDED

#include <string>
#include <functional>
#include <memory>
#include <map>
#include "stalk_request.h"
#include "stalk_response.h"
#include "stalk_connection_detail.h"

namespace Stalk
{

struct WebsocketSession;

using SendMsg = std::function<void(const std::string& msg)>;
using SendResponse = std::function<void(Response&& resp)>;
using WebsocketUpgrade = std::function<void(Request&& req)>;
using CloseSession = std::function<void(const std::string& reason)>;

using RequestVariables = std::map<std::string, std::string>;

using RoutedWebsocketPreUpgradeCb = std::function<void(ConnectionDetail, Request&&, RequestVariables&& variables, SendResponse&& send, WebsocketUpgrade&& upgrade)>;
using RoutedWebsocketConnectCb = std::function<void(bool connected, std::shared_ptr<WebsocketSession> session, RequestVariables&& variables)>;
using RoutedWebsocketReadCb = std::function<void(std::shared_ptr<WebsocketSession> session, std::string&& msg)>;

using RoutedHttpRequestCb = std::function<void(ConnectionDetail, Request&&, RequestVariables&& variables, SendResponse&& send)>;
using UnroutedRequestCb = std::function<void(Status, ConnectionDetail, Request&&, SendResponse&& send)>;

}

#endif
