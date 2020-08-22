#include "stalk/stalk_websocket_session.h"
#include "stalk_types_internal.h"
#include "stalk_websocket_session_impl.h"
#include "stalk/stalk_request.h"
#include "stalk_request_impl.h"
#include "stalk_connection_detail_builder.h"
#include "stalk/stalk_connection_detail_ostream.h"

namespace Stalk
{

WebsocketSession::WebsocketSession(std::shared_ptr<WebsocketSessionImpl> sessionImpl) :
    impl(sessionImpl)
{
}

WebsocketSession::~WebsocketSession() = default;

WebsocketSession::WebsocketSession(WebsocketSession&& other) :
    impl(other.impl)
{
}

WebsocketSession& WebsocketSession::operator=(WebsocketSession&& other)
{
    impl = other.impl;
    return *this;
}

uint64_t WebsocketSession::id() const
{
    return impl ? impl->id() : 0;
}

const ConnectionDetail& WebsocketSession::connectionDetail() const
{
    return impl->connectionDetail();
}

const Request& WebsocketSession::request() const
{
    return impl->request();
}

Request& WebsocketSession::request()
{
    return impl->request();
}

void WebsocketSession::send(const std::string& msg)
{
    impl->send(msg);
}

void WebsocketSession::close(const std::string& reason)
{
    /// \todo proper close with reason
    impl->stop();
}

std::ostream& operator<<(std::ostream& os, const WebsocketSession& session)
{
    //os << session.request;
    return os;
}


} // namespace Stalk
