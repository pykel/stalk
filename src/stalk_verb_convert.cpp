#include "stalk_verb_convert.h"
#include <iostream>
#include <boost/beast/http/verb.hpp>
#include "stalk/stalk_verb.h"

namespace Stalk
{

using verb = boost::beast::http::verb;

Verb verbFromBeastVerb(const verb v)
{
    switch (v)
    {
        case verb::delete_: return Verb::Delete;
        case verb::get: return Verb::Get;
        case verb::head: return Verb::Head;
        case verb::post: return Verb::Post;
        case verb::put: return Verb::Put;
        case verb::connect: return Verb::Connect;
        case verb::options: return Verb::Options;
        case verb::trace: return Verb::Trace;
        case verb::copy: return Verb::Copy;
        case verb::lock: return Verb::Lock;
        case verb::mkcol: return Verb::Mkcol;
        case verb::move: return Verb::Move;
        case verb::propfind: return Verb::Propfind;
        case verb::proppatch: return Verb::Proppatch;
        case verb::search: return Verb::Search;
        case verb::unlock: return Verb::Unlock;
        case verb::bind: return Verb::Bind;
        case verb::rebind: return Verb::Rebind;
        case verb::unbind: return Verb::Unbind;
        case verb::acl: return Verb::Acl;
        case verb::report: return Verb::Report;
        case verb::mkactivity: return Verb::Mkactivity;
        case verb::checkout: return Verb::Checkout;
        case verb::merge: return Verb::Merge;
        case verb::msearch: return Verb::Msearch;
        case verb::notify: return Verb::Notify;
        case verb::subscribe: return Verb::Subscribe;
        case verb::unsubscribe: return Verb::Unsubscribe;
        case verb::patch: return Verb::Patch;
        case verb::purge: return Verb::Purge;
        case verb::mkcalendar: return Verb::Mkcalendar;
        case verb::link: return Verb::Link;
        case verb::unlink: return Verb::Unlink;
        case verb::unknown: return Verb::Unknown;
    }

    return Verb::Unknown;
}

verb verbToBeastVerb(const Verb v)
{
    switch (v)
    {
        case Verb::Unknown: return verb::unknown;
        case Verb::Delete: return verb::delete_;
        case Verb::Get: return verb::get;
        case Verb::Head: return verb::head;
        case Verb::Post: return verb::post;
        case Verb::Put: return verb::put;
        case Verb::Connect: return verb::connect;
        case Verb::Options: return verb::options;
        case Verb::Trace: return verb::trace;
        case Verb::Copy: return verb::copy;
        case Verb::Lock: return verb::lock;
        case Verb::Mkcol: return verb::mkcol;
        case Verb::Move: return verb::move;
        case Verb::Propfind: return verb::propfind;
        case Verb::Proppatch: return verb::proppatch;
        case Verb::Search: return verb::search;
        case Verb::Unlock: return verb::unlock;
        case Verb::Bind: return verb::bind;
        case Verb::Rebind: return verb::rebind;
        case Verb::Unbind: return verb::unbind;
        case Verb::Acl: return verb::acl;
        case Verb::Report: return verb::report;
        case Verb::Mkactivity: return verb::mkactivity;
        case Verb::Checkout: return verb::checkout;
        case Verb::Merge: return verb::merge;
        case Verb::Msearch: return verb::msearch;
        case Verb::Notify: return verb::notify;
        case Verb::Subscribe: return verb::subscribe;
        case Verb::Unsubscribe: return verb::unsubscribe;
        case Verb::Patch: return verb::patch;
        case Verb::Purge: return verb::purge;
        case Verb::Mkcalendar: return verb::mkcalendar;
        case Verb::Link: return verb::link;
        case Verb::Unlink: return verb::unlink;
    }

    return verb::unknown;
}


std::ostream& operator<<(std::ostream& os, Verb v)
{
    os << verbToBeastVerb(v);
    return os;
}

} // namespace Stalk

