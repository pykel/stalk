#include "stalk_connection_detail_builder.h"
#include <functional>
#include <string>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "utils/crypto_utils.h"

namespace Stalk
{

namespace ConnectionDetailBuilder
{

static const std::string digestName = "sha256";

ConnectionDetail::Security build(const SSL* ssl);

Stalk::ConnectionDetail build(uint64_t id, const boost::asio::ip::tcp::socket& stream)
{
    Stalk::ConnectionDetail detail;
    detail.id = id;
    detail.peerAddress = stream.remote_endpoint().address().to_string();
    detail.peerPort = stream.remote_endpoint().port();
    return detail;
}

Stalk::ConnectionDetail build(uint64_t id, const boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream)
{
    Stalk::ConnectionDetail detail = build(id, stream.next_layer());
    detail.encrypted = true;
    const SSL* ssl = const_cast<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&>(stream).native_handle();

    detail.security = build(ssl);
    return detail;
}

Stalk::ConnectionDetail build(uint64_t id, const boost::beast::ssl_stream<boost::asio::ip::tcp::socket>& stream)
{
    Stalk::ConnectionDetail detail = build(id, stream.next_layer());
    detail.encrypted = true;
    const SSL* ssl = const_cast<boost::beast::ssl_stream<boost::asio::ip::tcp::socket>&>(stream).native_handle();

    detail.security = build(ssl);
    return detail;
}

ConnectionDetail::Security build(const SSL* ssl)
{
    if (!ssl)
    {
        return ConnectionDetail::Security();
    }

    auto buildCertDetail = [](const X509* cert) -> ConnectionDetail::Security::Cert
        {
            ConnectionDetail::Security::Cert certDetail;
            if (!cert)
                return certDetail;

            certDetail.digest = CryptoUtils::digest(cert, digestName);
            certDetail.commonName = CryptoUtils::commonName(cert);
            certDetail.issuer = CryptoUtils::issuer(cert);
            certDetail.pem = CryptoUtils::certAsPEM(cert);

            return certDetail;
        };

    ConnectionDetail::Security detail;

    detail.cipher.name = SSL_get_cipher(ssl);
    detail.cipher.bits = SSL_get_cipher_bits(ssl, nullptr);
    detail.cipher.version = SSL_get_cipher_version(ssl);

    X509* peerCert = SSL_get_peer_certificate(ssl);

    if (peerCert)
    {
        detail.peerCert = buildCertDetail(peerCert);
        X509_free(peerCert);
    }

    STACK_OF(X509)* peerCertStack = SSL_get_peer_cert_chain(ssl);
    if (peerCertStack)
    {
        for (int idx = 0; idx < sk_X509_num(peerCertStack); ++idx)
        {
            const X509* cert = sk_X509_value(peerCertStack, idx);
            if (cert)
                detail.peerCertStack.push_back(buildCertDetail(cert));
        }
    }

    return detail;
}

Stalk::ConnectionDetail::Security::Cert buildCertDetail(const X509* cert)
{
    ConnectionDetail::Security::Cert certDetail;
    if (!cert)
        return certDetail;

    certDetail.digest = CryptoUtils::digest(cert, digestName);
    certDetail.commonName = CryptoUtils::commonName(cert);
    certDetail.issuer = CryptoUtils::issuer(cert);
    certDetail.pem = CryptoUtils::certAsPEM(cert);

    return certDetail;
}

} // namespace ConnectionDetailBuilder
} // namespace Stalk
