#ifndef stalk_field_convert_INCLUDED
#define stalk_field_convert_INCLUDED

#include <boost/beast/http/field.hpp>
#include <iostream>
#include "stalk/stalk_field.h"

namespace Stalk
{

Field fieldFromBeast(const boost::beast::http::field);
boost::beast::http::field fieldToBeast(const Field field);

}

#endif
