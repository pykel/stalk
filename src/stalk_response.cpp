#include "stalk/stalk_response.h"
#include "stalk/stalk_request.h"
#include "stalk_request_impl.h"
#include "stalk_response_impl.h"
#include "stalk_field_convert.h"

namespace Stalk
{

Response::Response() :
    impl(std::make_unique<ResponseImpl>())
{
}

Response::Response(const Request& request) :
    impl(std::make_unique<ResponseImpl>(request.impl->request))
{
    impl->response.keep_alive(request.impl->request.keep_alive());
}

Response::~Response() = default;

Response::Response(Response&& other) :
    impl(std::move(other.impl))
{
}

Response::Response(const Response& other) :
    impl(new ResponseImpl(*other.impl))
{
}

Response& Response::operator=(Response&& other)
{
    impl = std::move(other.impl);
    return *this;
}

Response& Response::operator=(const Response& other)
{
    impl.reset(new ResponseImpl(*other.impl));
    return *this;
}

Response Response::build(const Request& req, Status status, const std::string& contentType, const std::string& body)
{
    return Response(req)
            .status(status)
            .set(Field::content_type, contentType)
            .body(body);
}

Response Response::build(const Request& req, Status status, std::string&& contentType, std::string&& body)
{
    return Response(req)
            .status(status)
            .set(Field::content_type, contentType)
            .body(body);
}

Response Response::build(const Request& req, Status status)
{
    return Response(req).status(status);
}

Response& Response::set(Field name, const std::string& value)
{
    impl->response.set(fieldToBeast(name), value);
    return *this;
}

Response& Response::set(Field name, std::string&& value)
{
    impl->response.set(fieldToBeast(name), std::move(value));
    return *this;
}

Response& Response::set(std::string_view name, const std::string& value)
{
    impl->response.set(boost::string_view(name.data(), name.size()), value);
    return *this;
}

Response& Response::set(std::string_view name, std::string&& value)
{
    impl->response.set(boost::string_view(name.data(), name.size()), std::move(value));
    return *this;
}

std::string Response::get(Field name)
{
    auto sv = impl->response.base()[fieldToBeast(name)];
    return std::string(sv.data(), sv.data() + sv.size());
}

Status Response::status() const
{
    return static_cast<Status>(impl->response.result());
}

Response& Response::status(unsigned s)
{
    impl->response.result(static_cast<boost::beast::http::status>(s));
    return *this;
}

Response& Response::status(Status s)
{
    impl->response.result(static_cast<boost::beast::http::status>(s));
    return *this;
}

bool Response::keepAlive() const
{
    return impl->response.keep_alive();
}

Response& Response::keepAlive(bool v)
{
    impl->response.keep_alive(v);
    return *this;
}

const std::string& Response::body() const
{
    return impl->response.body();
}

std::string& Response::body()
{
    return impl->response.body();
}

Response& Response::body(std::string&& b)
{
    impl->response.body() = std::move(b);
    impl->response.prepare_payload();
    return *this;
}

Response& Response::body(const std::string& b)
{
    impl->response.body() = b;
    impl->response.prepare_payload();
    return *this;
}

std::ostream& operator<<(std::ostream& os, const Response& resp)
{
    os << resp.impl->response;
    return os;
}


} // namespace Stalk
