#include "stalk/stalk_router.h"

namespace Stalk
{

Router::Router()
{
}

std::variant<Status, Router::MatchedHttpRoute> Router::getHttpRoute(const std::string& path, const Verb method)
{
    bool foundRoute = false;
    for (const auto& route : httpRoutes_)
    {
        auto matchResult = Route::pathRouteMatch(path, route.routeSegments(), route.acceptLongerPaths());
        if (matchResult.matched)
        {
            foundRoute = true;
            if (route.hasMethod(method))
            {
                return std::make_pair(route, matchResult.variables);
            }
        }
    }
    return foundRoute ? Status::method_not_allowed : Status::not_found;
}

std::optional<std::pair<Route::Websocket, RequestVariables>> Router::getWebsocketRoute(const std::string& path)
{
    for (const auto& route : websocketRoutes_)
    {
        auto matchResult = Route::pathRouteMatch(path, route.routeSegments(), route.acceptLongerPaths());
        if (matchResult.matched)
        {
            return std::make_pair(route, matchResult.variables);
        }
    }
    return std::optional<std::pair<Route::Websocket, RequestVariables>>();
}

void Router::addHttpRoute(Route::Http&& route)
{
    httpRoutes_.push_back(std::move(route));
    std::sort(httpRoutes_.begin(), httpRoutes_.end(), httpRouteCmp);
}

void Router::addWebsocketRoute(Route::Websocket&& route)
{
    websocketRoutes_.push_back(std::move(route));
    std::sort(websocketRoutes_.begin(), websocketRoutes_.end(), websocketRouteCmp);
}

bool Router::pathCmp(const std::string& lhs, const std::string& rhs)
{
    if (lhs.size() > rhs.size())
        return true;

    if (lhs.size() < rhs.size())
        return false;

    return lhs > rhs;
}

bool Router::httpRouteCmp(const Route::Http& lhs, const Route::Http& rhs)
{
    return pathCmp(lhs.path(), rhs.path());
}

bool Router::websocketRouteCmp(const Route::Websocket& lhs, const Route::Websocket& rhs)
{
    return pathCmp(lhs.path(), rhs.path());
}

} // namespace Stalk
