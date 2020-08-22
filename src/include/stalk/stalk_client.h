#ifndef stalk_client_INCLUDED
#define stalk_client_INCLUDED

#include <stdint.h>
#include <string>
#include <memory>
#include <functional>
#include "stalk_request.h"
#include "stalk_response.h"


namespace boost {

    namespace system {
        class error_code;
    }

    namespace asio {
        class io_context;

        namespace ssl {
            class context;
        }   // boost::asio::ssl

    } // asio
} // boost


namespace Stalk
{

class WebClientImpl;


// auto client = make_shared<WebClient>(ioc);
// auto state = client->get(url, []() {}, []() {});
// if (state != WebClient::State::InProgress) {}
// ...

// Create HTTP(s) client request.
class WebClient : public std::enable_shared_from_this<WebClient>
{
public:

    enum class State
    {
        Idle = 0,
        InProgress,
        ErrorRequestAlreadyInprogress
    };

    using ResponseCb = std::function<void(Response&&)>;
    using ErrorCb = std::function<void(const boost::system::error_code&, std::string&&)>;

    WebClient(boost::asio::io_context& ioc);
    ~WebClient();

    WebClient& key(const std::string& key);
    WebClient& cert(const std::string& cert);

    State get(const std::string& host, const std::string& port, bool ssl, const std::string& path,
             ResponseCb&& respCb, ErrorCb&& errorCb,
             const std::string& accept = "*/*");
    State post(const std::string& host, const std::string& port, bool ssl, const std::string& path,
              const std::string& contentType, std::string&& body,
              ResponseCb&& respCb, ErrorCb&& errorCb,
              const std::string& accept = "*/*");
    State req(const std::string& host, const std::string& port, bool ssl, const std::string& path,
             Verb method, const std::string& contentType, std::string&& body,
             ResponseCb&& respCb, ErrorCb&& errorCb,
             const std::string& accept = "*/*");
    State run(const std::string& host, const std::string& port, bool ssl,
             Request&& req, ResponseCb&& respCb, ErrorCb&& errorCb);

    bool stop();

    boost::asio::ssl::context& ctx();

    const State state() const;

private:

    std::unique_ptr<WebClientImpl> impl_;
};

} // namespace Stalk

#endif
