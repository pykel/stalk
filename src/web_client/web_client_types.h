#ifndef web_client_types_INCLUDED
#define web_client_types_INCLUDED

#include <functional>
#include <string>
#include <boost/system/error_code.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace WebClient
{
    typedef boost::beast::http::request<boost::beast::http::string_body> Request;
    typedef boost::beast::http::response<boost::beast::http::string_body> Response;

    typedef std::function<void(const Response&)> ResponseCb;
    typedef std::function<void(const boost::system::error_code&, const std::string&)> ErrorCb;

} // namespace WebClient

#endif // ifndef web_client_types_INCLUDED

