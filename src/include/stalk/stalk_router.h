#ifndef stalk_router_INCLUDED
#define stalk_router_INCLUDED

#include <string>
#include <functional>
#include <optional>
#include <variant>
#include <map>
#include "stalk_route.h"
#include "stalk_types.h"

namespace Stalk
{

class Router
{
public:
    Router();

    using MatchedHttpRoute = std::pair<Route::Http, RequestVariables>;
    std::variant<Status, MatchedHttpRoute> getHttpRoute(const std::string& path, const Verb method);
    std::optional<std::pair<Route::Websocket, RequestVariables>> getWebsocketRoute(const std::string& path);
    void addHttpRoute(Route::Http&& route);
    void removeHttpRoute(const std::string& path);
    void addWebsocketRoute(Route::Websocket&& route);
    void removeWebsocketRoute(const std::string& path);

private:

    static bool pathCmp(const std::string& lhs, const std::string& rhs);
    static bool httpRouteCmp(const Route::Http& lhs, const Route::Http& rhs);
    static bool websocketRouteCmp(const Route::Websocket& lhs, const Route::Websocket& rhs);

    std::vector<Route::Http> httpRoutes_;
    std::vector<Route::Websocket> websocketRoutes_;
};

} // namespace Stalk

#endif
