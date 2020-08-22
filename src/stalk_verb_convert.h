#ifndef stalk_verb_convert_INCLUDED
#define stalk_verb_convert_INCLUDED

#include "stalk/stalk_verb.h"
#include <boost/beast/http/verb.hpp>

namespace Stalk
{

Verb verbFromBeastVerb(const boost::beast::http::verb verb);
boost::beast::http::verb verbToBeastVerb(const Verb verb);

}

#endif

