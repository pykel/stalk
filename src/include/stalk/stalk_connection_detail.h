#ifndef stalk_connection_detail_INCLUDED
#define stalk_connection_detail_INCLUDED

#include <stdint.h>
#include <string>
#include <vector>


namespace Stalk
{

struct ConnectionDetail
{
    struct Security
    {
        struct Cert
        {
            std::string digest;
            std::string commonName;
            std::string issuer;
            std::string pem;
        };

        struct Cipher
        {
            std::string name;
            int bits = 0;
            std::string version;
        };

        Cipher cipher;
        Cert peerCert;
        std::vector<Cert> peerCertStack;
    };

    ConnectionDetail& operator=(const ConnectionDetail& b) = default;

    uint64_t id = 0;
    bool encrypted = false;
    Security security;
    std::string peerAddress;
    uint16_t peerPort = 0;
};

} // namespace Stalk

#endif

