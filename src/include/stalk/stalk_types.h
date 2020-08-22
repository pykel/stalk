#ifndef stalk_types_INCLUDED
#define stalk_types_INCLUDED

#include <string>
#include <functional>
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

typedef std::map<std::string, std::string> RequestVariables;

typedef std::function<void(ConnectionDetail, Request&&, RequestVariables&& variables, SendResponse&& send, WebsocketUpgrade&& upgrade)> RoutedWebsocketPreUpgradeCb;
typedef std::function<void(bool connected, std::shared_ptr<WebsocketSession> session, RequestVariables&& variables)> RoutedWebsocketConnectCb;
typedef std::function<void(std::shared_ptr<WebsocketSession> session, std::string&& msg)> RoutedWebsocketReadCb;

typedef std::function<void(ConnectionDetail, Request&&, RequestVariables&& variables, SendResponse&& send)> RoutedHttpRequestCb;

}

#endif
