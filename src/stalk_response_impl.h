#pragma once

#include <memory>
#include "stalk_types_internal.h"

namespace Stalk
{

struct ResponseImpl
{
    ResponseImpl() = default;

    ResponseImpl(const BeastRequest& request) :
        response(boost::beast::http::status::internal_server_error, request.version())
    {
    }

    BeastResponse response;
};

} // namespace Stalk
