#pragma once

#include "stalk_connection_detail.h"
#include <fmt/format.h>


template<>
struct fmt::formatter<Stalk::ConnectionDetail::Security::Cert>
{
    template<typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }


    template<typename FormatContext>
    auto format(const Stalk::ConnectionDetail::Security::Cert& cert, FormatContext& ctx)
    {
        return fmt::format_to(ctx.out(), "commonName:{0},digest:{1},issuer:{2},pem:{3}", cert.commonName, cert.digest, cert.issuer, cert.pem);
    }
};

template<>
struct fmt::formatter<Stalk::ConnectionDetail>
{
    template<typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
        return ctx.begin();
    }


    template<typename FormatContext>
    auto format(const Stalk::ConnectionDetail& detail, FormatContext& ctx)
    {
        const auto& sec = detail.security;
        return fmt::format_to(ctx.out(),
            "remote:[{0}:{1}],encrypted:{2},cipher:[name:{3},bits:{4},version:{5},peer:[{6}]",
              detail.peerAddress, detail.peerPort,
              detail.encrypted ? "true" : "false",
              sec.cipher.name, sec.cipher.bits, sec.cipher.version,
              sec.peerCert);
    }
};
