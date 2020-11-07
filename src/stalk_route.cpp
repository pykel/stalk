#include "stalk/stalk_route.h"

#include <functional>
#include <numeric>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
//#include "stalk_verb.h"
//#include "stalk_request.h"
//#include "stalk_response.h"
//#include "stalk_websocket_session.h"
//#include "stalk_types.h"

namespace Stalk
{

namespace Route
{
    std::vector<std::string> splitPath(const std::string& path)
    {
        const auto is_sep = [](const auto v) { return v == '/'; };
        const auto trimmed = boost::algorithm::trim_copy_if(path, is_sep);

        std::vector<std::string> components;
        boost::split(components, trimmed, is_sep, boost::algorithm::token_compress_mode_type::token_compress_on);
        return components;
    }

    void processQueryParams(const std::string& queryString, RequestVariables& params)
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
    MatchResult pathRouteMatch(const std::string& srcPath, const std::vector<RouteSegment>& matchRouteSegments, bool acceptLongerPaths)
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

    std::vector<RouteSegment> routeDefinitionParse(const std::string& pathDefinition)
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

    Http::Http(const std::string& path, const std::set<Verb>& methods, RoutedHttpRequestCb requestCb) :
        path_(path), methods_(methods), requestCb_(requestCb)
    {
        routeSegments_ = routeDefinitionParse(path);
    }

    Http& Http::setAcceptLongerPaths(bool acceptLongerPaths)
    {
        acceptLongerPaths_ = acceptLongerPaths;
        return *this;
    }

    const std::string& Http::path() const
    {
        return path_;
    }

    const std::vector<RouteSegment>& Http::routeSegments() const
    {
        return routeSegments_;
    }

    const std::set<Verb>& Http::methods() const
    {
        return methods_;
    }

    bool Http::hasMethod(const Verb& method) const
    {
        return methods_.find(method) != methods_.end();
    }

    bool Http::acceptLongerPaths() const
    {
        return acceptLongerPaths_;
    }

    Http& Http::setRequestCb(RoutedHttpRequestCb cb)
    {
        requestCb_ = cb;
        return *this;
    }

    const RoutedHttpRequestCb& Http::requestCb() const
    {
        return requestCb_;
    }


    Websocket::Websocket(const std::string& path,
              RoutedWebsocketPreUpgradeCb preUpgradeCb,
              RoutedWebsocketConnectCb connectCb,
              RoutedWebsocketReadCb readCb) :
        path_(path), preUpgradeCb_(preUpgradeCb), connectCb_(connectCb), readCb_(readCb)
    {
        routeSegments_ = routeDefinitionParse(path);
    }

    Websocket& Websocket::setAcceptLongerPaths(bool acceptLongerPaths)
    {
        acceptLongerPaths_ = acceptLongerPaths;
        return *this;
    }

    const std::string& Websocket::path() const
    {
        return path_;
    }

    const std::vector<RouteSegment>& Websocket::routeSegments() const
    {
        return routeSegments_;
    }

    bool Websocket::acceptLongerPaths() const
    {
        return acceptLongerPaths_;
    }

    Websocket& Websocket::setPreUpgradeCb(RoutedWebsocketPreUpgradeCb cb)
    {
        preUpgradeCb_ = cb;
        return *this;
    }

    Websocket& Websocket::setConnectCb(RoutedWebsocketConnectCb cb)
    {
        connectCb_ = cb;
        return *this;
    }

    Websocket& Websocket::setReadCb(RoutedWebsocketReadCb cb)
    {
        readCb_ = cb;
        return *this;
    }

    const RoutedWebsocketPreUpgradeCb& Websocket::preUpgradeCb() const
    {
        return preUpgradeCb_;
    }

    const RoutedWebsocketConnectCb& Websocket::connectCb() const
    {
        return connectCb_;
    }

    const RoutedWebsocketReadCb& Websocket::readCb() const
    {
        return readCb_;
    }

} // namespace Route

} // namespace Stalk
