#include "stalk/stalk_request.h"
#include "stalk_request_impl.h"
#include "stalk_field_convert.h"
#include "stalk_verb_convert.h"

namespace Stalk
{

Request::Request(std::unique_ptr<RequestImpl> requestImpl) :
    impl(std::move(requestImpl))
{
}

Request::Request() :
    impl(std::make_unique<RequestImpl>())
{
}

Request::~Request() = default;

Request::Request(Request&& other) :
    impl(std::move(other.impl))
{
}

Request::Request(const Request& other) :
    impl(new RequestImpl(*other.impl))
{
}

Request& Request::operator=(Request&& other)
{
    impl = std::move(other.impl);
    return *this;
}

Request& Request::operator=(const Request& other)
{
    impl.reset(new RequestImpl(*other.impl));
    return *this;
}

Request& Request::set(Field name, const std::string& value)
{
    impl->request.set(fieldToBeast(name), value);
    return *this;
}
Request& Request::set(Field name, std::string&& value)
{
    impl->request.set(fieldToBeast(name), std::move(value));
    return *this;
}

Request& Request::set(std::string_view name, const std::string& value)
{
    impl->request.set(boost::string_view(name.data(), name.size()), std::move(value));
    return *this;
}
Request& Request::set(std::string_view name, std::string&& value)
{
    impl->request.set(boost::string_view(name.data(), name.size()), std::move(value));
    return *this;
}

std::string Request::get(Field name) const
{
    auto sv = impl->request.base()[fieldToBeast(name)];
    return std::string(sv.data(), sv.data() + sv.size());
}

bool Request::has(Field name) const
{
    return impl->request.base().find(fieldToBeast(name)) != impl->request.base().end();
}


unsigned Request::version() const
{
    return impl->request.version();
}

Request& Request::version(unsigned v)
{
    impl->request.version(v);
    return *this;
}

bool Request::keepAlive() const
{
    return impl->request.keep_alive();
}

Request& Request::keepAlive(bool v)
{
    impl->request.keep_alive(v);
    return *this;
}

Verb Request::method() const
{
    return verbFromBeastVerb(impl->request.method());
}

Request& Request::method(Verb v)
{
    impl->request.method(verbToBeastVerb(v));
    return *this;
}

std::string_view Request::target() const
{
    const auto sv = impl->request.target();
    return std::string_view(sv.data(), sv.size());
}

std::string Request::targetStr() const
{
    const auto sv = impl->request.target();
    return std::string(sv.data(), sv.data() + sv.size());
}

Request& Request::target(const std::string& t)
{
    impl->request.target(t);
    return *this;
}

const std::string& Request::body() const
{
    return impl->request.body();
}

std::string& Request::body()
{
    return impl->request.body();
}

Request& Request::body(std::string&& b)
{
    impl->request.body() = std::move(b);
    return *this;
}

Request& Request::body(const std::string& b)
{
    impl->request.body() = b;
    return *this;
}

std::ostream& operator<<(std::ostream& os, const Request& req)
{
    os << req.impl->request;
    return os;
}


} // namespace Stalk
