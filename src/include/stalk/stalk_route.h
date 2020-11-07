#ifndef stalk_route_INCLUDED
#define stalk_route_INCLUDED

#include <string>
#include <functional>
#include <vector>
#include <set>
#include "stalk_verb.h"
#include "stalk_types.h"

namespace Stalk
{

namespace Route
{
    struct RouteSegment
    {
        RouteSegment(const std::string& path, bool isVariable, bool isRequired = true) : path(path), isVariable(isVariable), isRequired(isRequired) {}

        std::string path;
        bool isVariable;
        bool isRequired;
    };

    struct MatchResult
    {
        bool matched;
        RequestVariables variables;
    };

    std::vector<std::string> splitPath(const std::string& path);

    void processQueryParams(const std::string& queryString, RequestVariables& params);

    /// Check if this Route matches a path and populate route variables.
    MatchResult pathRouteMatch(const std::string& srcPath, const std::vector<RouteSegment>& matchRouteSegments, bool acceptLongerPaths);

    std::vector<RouteSegment> routeDefinitionParse(const std::string& pathDefinition);

    class Http
    {
    public:

        Http(const std::string& path, const std::set<Verb>& methods, RoutedHttpRequestCb requestCb = RoutedHttpRequestCb());

        Http& setAcceptLongerPaths(bool acceptLongerPaths = true);

        const std::string& path() const;
        const std::vector<RouteSegment>& routeSegments() const;
        const std::set<Verb>& methods() const;
        bool hasMethod(const Verb& method) const;
        bool acceptLongerPaths() const;
        Http& setRequestCb(RoutedHttpRequestCb cb);
        const RoutedHttpRequestCb& requestCb() const;

    private:
        std::string path_;
        std::vector<RouteSegment> routeSegments_;
        std::set<Verb> methods_;
        RoutedHttpRequestCb requestCb_;
        bool acceptLongerPaths_ = true;
    };

    class Websocket
    {
    public:
        Websocket(const std::string& path,
                  RoutedWebsocketPreUpgradeCb preUpgradeCb = RoutedWebsocketPreUpgradeCb(),
                  RoutedWebsocketConnectCb connectCb = RoutedWebsocketConnectCb(),
                  RoutedWebsocketReadCb readCb = RoutedWebsocketReadCb());
        Websocket& setAcceptLongerPaths(bool acceptLongerPaths = true);

        const std::string& path() const;
        const std::vector<RouteSegment>& routeSegments() const;
        bool acceptLongerPaths() const;

        Websocket& setPreUpgradeCb(RoutedWebsocketPreUpgradeCb cb);
        Websocket& setConnectCb(RoutedWebsocketConnectCb cb);
        Websocket& setReadCb(RoutedWebsocketReadCb cb);

        const RoutedWebsocketPreUpgradeCb& preUpgradeCb() const;
        const RoutedWebsocketConnectCb& connectCb() const;
        const RoutedWebsocketReadCb& readCb() const;

    private:
        std::string path_;
        std::vector<RouteSegment> routeSegments_;
        RoutedWebsocketPreUpgradeCb preUpgradeCb_;
        RoutedWebsocketConnectCb connectCb_;
        RoutedWebsocketReadCb readCb_;
        bool acceptLongerPaths_ = true;
    };

} // namespace Route

} // namespace Stalk

#endif
