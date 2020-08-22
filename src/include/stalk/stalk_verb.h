#ifndef stalk_verb_INCLUDED
#define stalk_verb_INCLUDED

#include <iostream>

namespace Stalk
{

enum class Verb
{
    Unknown = 0,
    Delete,
    Get,
    Head,
    Post,
    Put,
    Connect,
    Options,
    Trace,
    // WebDAV
    Copy,
    Lock,
    Mkcol,
    Move,
    Propfind,
    Proppatch,
    Search,
    Unlock,
    Bind,
    Rebind,
    Unbind,
    Acl,
    // subversion
    Report,
    Mkactivity,
    Checkout,
    Merge,
    // upnp
    Msearch,
    Notify,
    Subscribe,
    Unsubscribe,
    // RFC-5789
    Patch,
    Purge,
    // CalDAV
    Mkcalendar,
    // RFC-2068, section 19.6.1.2
    Link,
    Unlink
};

std::ostream& operator<<(std::ostream&, Verb);

inline const char* verbString(Verb verb)
{
    switch (verb)
    {
        case Verb::Unknown:
            return "unknown";
        case Verb::Delete:
            return "delete";
        case Verb::Get:
            return "get";
        case Verb::Head:
            return "head";
        case Verb::Post:
            return "post";
        case Verb::Put:
            return "put";
        case Verb::Connect:
            return "connect";
        case Verb::Options:
            return "options";
        case Verb::Trace:
            return "trace";
        case Verb::Copy:
            return "copy";
        case Verb::Lock:
            return "lock";
        case Verb::Mkcol:
            return "mkcol";
        case Verb::Move:
            return "move";
        case Verb::Propfind:
            return "propfind";
        case Verb::Proppatch:
            return "proppatch";
        case Verb::Search:
            return "search";
        case Verb::Unlock:
            return "unlock";
        case Verb::Bind:
            return "bind";
        case Verb::Rebind:
            return "rebind";
        case Verb::Unbind:
            return "unbind";
        case Verb::Acl:
            return "acl";
        case Verb::Report:
            return "report";
        case Verb::Mkactivity:
            return "mkactivity";
        case Verb::Checkout:
            return "checkout";
        case Verb::Merge:
            return "merge";
        case Verb::Msearch:
            return "msearch";
        case Verb::Notify:
            return "notify";
        case Verb::Subscribe:
            return "subscribe";
        case Verb::Unsubscribe:
            return "unsubscribe";
        case Verb::Patch:
            return "patch";
        case Verb::Purge:
            return "purge";
        case Verb::Mkcalendar:
            return "mkcalendar";
        case Verb::Link:
            return "link";
        case Verb::Unlink:
            return "unlink";
    }

    return "Unknown";
}

}

#endif
