#pragma once

#include <iostream>
#include "stalk_connection_detail.h"

namespace Stalk
{

inline std::ostream& operator<<(std::ostream& os, const ConnectionDetail::Security::Cert& cert)
{
    os << "commonName:" << cert.commonName
       << ",digest:" << cert.digest
       << ",pem:" << cert.pem
       << ",issuer:" << cert.issuer;
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const ConnectionDetail& connectionDetail)
{
    os << "remote:[" << connectionDetail.peerAddress << ":" << connectionDetail.peerPort << "]"
       << " encrypted:[" << (connectionDetail.encrypted ? "true" : "false") << "]";

    if (!connectionDetail.encrypted)
        return os;

    const ConnectionDetail::Security& detail = connectionDetail.security;

    os << " cipher:[name:" << detail.cipher.name << ",bits:" << detail.cipher.bits
       << ",version:" << detail.cipher.version << "]";

    if (!detail.peerCert.digest.empty())
    {
        os << " peerCert:[" << detail.peerCert << "]";
    }

    if (!detail.peerCertStack.empty())
    {
        os << " peerCertStack:[";
        bool have = false;
        for (const auto& cert : detail.peerCertStack)
        {
            if (have)
                os << ",";
            os << "[" << cert << "]";
            have = true;
        }
        os << "]";
    }
    return os;
}

} // namespace Stalk
