#pragma once

#include <string>
#include <string_view>
#include <memory>
#include "stalk_field.h"
#include "stalk_verb.h"


namespace Stalk
{

struct RequestImpl;

struct Request
{
    Request(std::unique_ptr<RequestImpl> req);
    Request();
    ~Request();

    Request(Request&& other);
    Request(const Request& other);
    Request& operator=(const Request& other);
    Request& operator=(Request&& other);

    Request& set(Field name, const std::string& value);
    Request& set(Field name, std::string&& value);

    Request& set(std::string_view name, const std::string& value);
    Request& set(std::string_view name, std::string&& value);

    std::string get(Field name) const;
    bool has(Field name) const;

    unsigned version() const;
    /// Set the HTTP version (11 = 1.1, 10 = 1.0). Defaults to 11.
    Request& version(unsigned v);

    bool keepAlive() const;
    Request& keepAlive(bool v);

    Verb method() const;
    Request& method(Verb v);

    Request& target(const std::string& t);
    std::string_view target() const;
    std::string targetStr() const;

    const std::string& body() const;
    std::string& body();

    Request& body(std::string&& b);
    Request& body(const std::string& b);

    std::unique_ptr<RequestImpl> impl;
};

std::ostream& operator<<(std::ostream&, const Request&);

} // namespace Stalk
