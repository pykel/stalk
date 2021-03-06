#pragma once

#include <memory>
#include "stalk_types_internal.h"

namespace Stalk
{

struct RequestImpl
{
    RequestImpl(BeastRequest&& req) : request(std::move(req)) {}
    RequestImpl(const BeastRequest& req) : request(req) {}
    RequestImpl() = default;

    BeastRequest request;
};

} // namespace Stalk
