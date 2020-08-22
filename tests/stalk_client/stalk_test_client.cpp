#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include "stalk/stalk_client.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
    }

    boost::asio::io_context ioc;

    auto client = std::make_shared<Stalk::WebClient>(ioc);

    ioc.run();

    return 0;
}

