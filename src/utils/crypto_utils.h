#ifndef crypto_utils_INCLUDED
#define crypto_utils_INCLUDED

#include <functional>
#include <string>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "utils/string_hex.h"

namespace CryptoUtils
{

inline std::string digest(const X509* cert, const std::string& digestName = "sha1")
{
    uint8_t buf[1024];
    unsigned int len = 1024;
    const EVP_MD* digest = EVP_get_digestbyname(digestName.c_str());
    X509_digest(cert, digest, buf, &len);
    return StringUtils::toHexString(static_cast<uint8_t*>(buf), static_cast<uint8_t*>(buf) + len);
}


inline std::string certIssuerField(const X509* cert, int nid)
{
    std::string ret;
    int idx = X509_NAME_get_index_by_NID(X509_get_issuer_name(const_cast<X509*>(cert)), nid, -1);
    if (idx != -1)
    {
        X509_NAME_ENTRY *ne = X509_NAME_get_entry(X509_get_subject_name(const_cast<X509*>(cert)), idx);
        ASN1_STRING *s = X509_NAME_ENTRY_get_data(ne);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ret = std::string(reinterpret_cast<char*>(ASN1_STRING_data(s)), ASN1_STRING_length(s));
#else
        ret = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)), ASN1_STRING_length(s));
#endif
    }
    return ret;
}

inline std::string certSubjectField(const X509* cert, int nid)
{
    std::string ret;
    int idx = X509_NAME_get_index_by_NID(X509_get_subject_name(const_cast<X509*>(cert)), nid, -1);
    if (idx != -1)
    {
        X509_NAME_ENTRY *ne = X509_NAME_get_entry(X509_get_subject_name(const_cast<X509*>(cert)), idx);
        ASN1_STRING *s = X509_NAME_ENTRY_get_data(ne);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ret = std::string(reinterpret_cast<char*>(ASN1_STRING_data(s)), ASN1_STRING_length(s));
#else
        ret = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)), ASN1_STRING_length(s));
#endif
    }
    return ret;
}

inline std::string issuer(const X509* cert)
{
    return certIssuerField(cert, NID_commonName);
}

inline std::string commonName(const X509* cert)
{
    return certSubjectField(cert, NID_commonName);
}

inline std::string certAsPEM(const X509* cert)
{
    std::string pem;
    // pem
    char* data;
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        PEM_write_bio_X509(bio, const_cast<X509*>(cert));
        unsigned int len = BIO_get_mem_data(bio, &data);

        pem.assign(data, len);

        BIO_free(bio);
    }
    return pem;
}

} // namespace CryptoUtils

#endif
