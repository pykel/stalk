#ifndef stalk_connection_detail_builder_INCLUDED
#define stalk_connection_detail_builder_INCLUDED

#include <openssl/ssl.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/version.hpp>
#if BOOST_BEAST_VERSION < 219
#include <boost/beast/experimental/core/ssl_stream.hpp>
#else
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#endif
#include "stalk/stalk_connection_detail.h"

namespace Stalk
{

namespace ConnectionDetailBuilder
{

Stalk::ConnectionDetail build(uint64_t id, const boost::asio::ip::tcp::socket& stream);
Stalk::ConnectionDetail build(uint64_t id, const boost::beast::tcp_stream& stream);
Stalk::ConnectionDetail build(uint64_t id, const boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream);
Stalk::ConnectionDetail build(uint64_t id, const boost::beast::ssl_stream<boost::beast::tcp_stream>& stream);

Stalk::ConnectionDetail::Security::Cert buildCertDetail(const X509* cert);

} // namespace ConnectionDetailBuilder
} // namespace Stalk

#endif
