#ifndef stalk_route_INCLUDED
#define stalk_route_INCLUDED

#include <string>
#include <functional>
#include <numeric>
#include <vector>
#include <map>
#include <set>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include "stalk_verb.h"
#include "stalk_request.h"
#include "stalk_response.h"
#include "stalk_websocket_session.h"
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

    inline std::vector<std::string> splitPath(const std::string& path)
    {
        const auto is_sep = [](const auto v) { return v == '/'; };
        const auto trimmed = boost::algorithm::trim_copy_if(path, is_sep);

        std::vector<std::string> components;
        boost::split(components, trimmed, is_sep, boost::algorithm::token_compress_mode_type::token_compress_on);
        return components;
    }

    inline void processQueryParams(const std::string& queryString, RequestVariables& params)
    {
        // this=that&something&var2=val8
        enum class State
        {
            Variable = 0,
            Value
        };

        State state = State::Variable;
        std::string variable;
        std::string value;
        for (const auto d : queryString)
        {
            switch (d)
            {
                case '&':
                    if (!variable.empty())
                        params[variable] = value;

                    variable.clear();
                    value.clear();
                    state = State::Variable;
                    break;

                case '=':
                    state = State::Value;
                    break;

                default:
                    if (state == State::Variable)
                        variable.push_back(d);
                    else
                        value.push_back(d);
                    break;
            }
        }
        if (!variable.empty())
            params[variable] = value;
    }

    /// Check if this Route matches a path and populate route variables.
    inline MatchResult pathRouteMatch(const std::string& srcPath, const std::vector<RouteSegment>& matchRouteSegments, bool acceptLongerPaths)
    {
        MatchResult matchResult { false, RequestVariables() };

        std::vector<std::string> pathQuerySplit;
        boost::split(pathQuerySplit, srcPath, [](const auto v) { return v == '?'; }, boost::algorithm::token_compress_mode_type::token_compress_on);
        if (pathQuerySplit.empty())
        {
            return matchResult;
        }

        auto components = splitPath(pathQuerySplit[0]);

        unsigned int requiredMinimumComponentsCount = std::accumulate(matchRouteSegments.begin(), matchRouteSegments.end(), (unsigned int)0,
                                                                      [](unsigned int v, const RouteSegment& s) { return v + (s.isRequired ? 1 : 0); });
        if (components.size() < requiredMinimumComponentsCount)
        {
            // provided path is less specific than this route - no match
            return matchResult;
        }

        if (!acceptLongerPaths && components.size() > matchRouteSegments.size())
        {
            // provided path is more specific than this route - no match
            return matchResult;
        }

        if (pathQuerySplit.size() > 1)
        {
            processQueryParams(pathQuerySplit[1], matchResult.variables);
        }

        for (size_t i = 0; i < matchRouteSegments.size(); ++i)
        {
            const auto& route = matchRouteSegments[i];

            if (i >= components.size() && !route.isRequired) // maybe an optional RouteSegment
            {
                continue;
            }

            const auto& component = components[i];

            if (route.isVariable)
            {
                matchResult.variables[route.path] = component;
            }
            else if (route.path != component)
            {
                return matchResult;
            }
        }

        matchResult.matched = true;
        return matchResult;
    }

    inline std::vector<RouteSegment> routeDefinitionParse(const std::string& pathDefinition)
    {
        std::vector<RouteSegment> routeSegments;
        // Create the route segments
        auto components = splitPath(pathDefinition);

        for (auto& component : components)
        {
            bool isVariable = component[0] == ':' || component[0] == '?';
            bool isRequired = component[0] != '?';
            if (isVariable)
            {
                // remove all ':' or '?' from var
                component.erase(std::remove_if(component.begin(), component.end(), [](auto x) { return x == ':' || x == '?'; }), component.end());
            }
            routeSegments.push_back(RouteSegment(component, isVariable, isRequired));
        }

        return routeSegments;
    }


    class Http
    {
    public:

        Http(const std::string& path, const std::set<Verb>& methods, RoutedHttpRequestCb requestCb = RoutedHttpRequestCb()) :
            path_(path), methods_(methods), requestCb_(requestCb)
        {
            routeSegments_ = routeDefinitionParse(path);
        }

        Http& setAcceptLongerPaths(bool acceptLongerPaths = true) { acceptLongerPaths_ = acceptLongerPaths; return *this; }

        const std::string& path() const { return path_; }
        const std::vector<RouteSegment>& routeSegments() const { return routeSegments_; }
        const std::set<Verb>& methods() const { return methods_; }
        bool hasMethod(const Verb& method) const { return methods_.find(method) != methods_.end(); }
        bool acceptLongerPaths() const { return acceptLongerPaths_; }
        Http& setRequestCb(RoutedHttpRequestCb cb) { requestCb_ = cb; return *this; }
        const RoutedHttpRequestCb& requestCb() const { return requestCb_; }

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
                  RoutedWebsocketReadCb readCb = RoutedWebsocketReadCb()) :
            path_(path), preUpgradeCb_(preUpgradeCb), connectCb_(connectCb), readCb_(readCb)
        {
            routeSegments_ = routeDefinitionParse(path);
        }

        Websocket& setAcceptLongerPaths(bool acceptLongerPaths = true) { acceptLongerPaths_ = acceptLongerPaths; return *this; }

        const std::string& path() const { return path_; }
        const std::vector<RouteSegment>& routeSegments() const { return routeSegments_; }
        bool acceptLongerPaths() const { return acceptLongerPaths_; }

        Websocket& setPreUpgradeCb(RoutedWebsocketPreUpgradeCb cb) { preUpgradeCb_ = cb; return *this; }
        Websocket& setConnectCb(RoutedWebsocketConnectCb cb) { connectCb_ = cb; return *this; }
        Websocket& setReadCb(RoutedWebsocketReadCb cb) { readCb_ = cb; return *this; }

        const RoutedWebsocketPreUpgradeCb& preUpgradeCb() const { return preUpgradeCb_; }
        const RoutedWebsocketConnectCb& connectCb() const { return connectCb_; }
        const RoutedWebsocketReadCb& readCb() const { return readCb_; }

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
