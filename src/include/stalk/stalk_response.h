#pragma once

#include <string>
#include <memory>
#include "stalk_field.h"
#include "stalk_status.h"


namespace Stalk
{

struct Request;

struct ResponseImpl;

struct Response
{
    Response();

    /// Construct from Request.
    Response(const Request& request);
    ~Response();

    Response(Response&& other);
    Response(const Response& other);
    Response& operator=(const Response& other);
    Response& operator=(Response&& other);

    static Response build(const Request& req, Status status, const std::string& contentType, const std::string& body);
    static Response build(const Request& req, Status status, std::string&& contentType, std::string&& body);
    static Response build(const Request& req, Status status);

    Response& set(Field name, const std::string& value);
    Response& set(Field name, std::string&& value);

    Response& set(std::string_view name, const std::string& value);
    Response& set(std::string_view name, std::string&& value);

    std::string get(Field name);

    Status status() const;
    Response& status(unsigned s);
    Response& status(Status s);

    bool keepAlive() const;
    Response& keepAlive(bool v);

    const std::string& body() const;
    std::string& body();

    Response& body(std::string&& b);
    Response& body(const std::string& b);

    std::unique_ptr<ResponseImpl> impl;
};

std::ostream& operator<<(std::ostream&, const Response&);

} // namespace Stalk
