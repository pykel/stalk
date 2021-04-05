#pragma once

#include <boost/beast/http/field.hpp>
#include <iostream>
#include "stalk/stalk_field.h"

namespace Stalk
{

Field fieldFromBeast(const boost::beast::http::field);
boost::beast::http::field fieldToBeast(const Field field);

}
