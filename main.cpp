#include <mini/logger.h>
#include <mini/console.h>
#include <mini/crypto/random.h>
#include <mini/io/stream_reader.h>
#include <mini/io/file.h>
#include <mini/tor/circuit.h>
#include <mini/tor/consensus.h>
#include <mini/tor/tor_socket.h>
#include <mini/tor/tor_stream.h>
#include <mini/net/http.h>
#include <mini/net/ssl_stream.h>
#include <mini/net/uri.h>

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <vector>
#include <set>
#include "gumbo-parser/gumbo.h"
#include <regex>

// gumbo-query headers
#include <Document.h>
#include <Selection.h>
#include <Node.h>

// https://habr.com/ru/post/508106/
// 
// for gumbo-query examples see gumbo-query/example folder
void process(const mini::byte_buffer_ref content)
{
    std::string page(content.get_size(), 0);
    memcpy(page.data(), content.get_buffer(), content.get_size());
    CDocument doc;
    doc.parse(page.c_str());
    CSelection c = doc.find("h1 a.special");
    CNode node = c.nodeAt(0);
    //printf("Node: %s\n", node.text().c_str());
    //std::string content = page.substr(node.startPos(), node.endPos() - node.startPos());
    //printf("Node: %s\n", content.c_str());
}

#define MINI_TOR_USE_CONSENSUS_CACHE 1
class tor_client
{
public:
    tor_client(void)
    {
        _consensus.set_allowed_dir_ports({ 80, 443 });
    }

    ~tor_client(void)
    {
        delete _circuit;
    }

    void extend_to_random(mini::tor::onion_router::status_flags flags, mini::collections::list<uint16_t> or_ports = {})
    {
        auto routers = _consensus.get_onion_routers_by_criteria(
            {
                {}, or_ports, _forbidden_onion_routers, flags
            });
        auto random_router = routers[mini::crypto::random_device.get_random(routers.get_size())];
        if (random_router)
        {
            _forbidden_onion_routers.add(random_router);
            extend_to(random_router);
        }
    }

    void extend_to(mini::tor::onion_router* onion_router)
    {
        if (_circuit == nullptr)
        {
            mini_info(
                "Connecting to node #%u: '%s' (%s:%u)",
                get_hop_count() + 1,
                onion_router->get_name().get_buffer(),
                onion_router->get_ip_address().to_string().get_buffer(),
                onion_router->get_or_port());
            _socket.connect(onion_router);
            if (_socket.is_connected())
            {
                _circuit = _socket.create_circuit();
                if (get_hop_count() == 1)
                {
                    mini_info("Connected...");
                }
                else
                {
                    mini_error("Error while creating circuit!");
                }
            }
            else
            {
                mini_error("Error while connecting!");
            }
        }
        else
        {
            mini_info(
                "Extending to node #%u: '%s' (%s:%u)",
                get_hop_count() + 1,
                onion_router->get_name().get_buffer(),
                onion_router->get_ip_address().to_string().get_buffer(),
                onion_router->get_or_port());
            auto previous_hop_count = get_hop_count();
            _circuit->extend(onion_router);
            if (get_hop_count() == (previous_hop_count + 1))
            {
                mini_info("Extended...");
            }
            else
            {
                delete _circuit;
                _circuit = nullptr;
                mini_warning("Error when extending!");
            }
        }
    }

    void extend_to(const mini::string_ref onion_router_name)
    {
        mini::tor::onion_router* router = _consensus.get_onion_router_by_name(onion_router_name);
        if (router)
        {
            extend_to(router);
        }
    }

    mini::string http_get(const mini::net::uri& url)
    {
        //
        // take out the parts to local variables.
        //
        const auto domain = url.get_domain();
        const auto host = url.get_host();
        const auto path = url.get_path();
        const auto port = url.get_port();
        const bool use_ssl = url.get_protocol().equals("https://");
        mini_info("Accessing '%s'", url.get_url().get_buffer());
        mini::io::stream* stream;
        mini::ptr<mini::tor::tor_stream> stream_tor;
        mini::ptr<mini::net::ssl_stream> stream_ssl;
        if (domain.ends_with(".onion"))
        {
            //
            // parse out the domain name without ".onion" extension.
            //
            mini::string onion = domain.substring(0, domain.get_size() - 6);
            mini_info("Creating onion stream...");
            stream_tor = _circuit->create_onion_stream(onion, port);
        }
        else
        {
            mini_info("Creating stream...");
            stream_tor = _circuit->create_stream(host, port);
        }
        if (stream_tor)
        {
            mini_info("Created...");
            stream = stream_tor.get();
        }
        else
        {
            mini_error("Error while creating the onion stream");
            return mini::string();
        }
        mini_info("Sending request...");
        mini::string result;
        if (use_ssl)
        {
            //
            // wrap ssl_stream around tor_stream.
            //
            stream_ssl = new mini::net::ssl_stream(*stream_tor, host);
            if (!stream_ssl->handshake(host, port))
            {
                mini_error("Error while establishing TLS with '%s'", host.get_buffer());
                return mini::string();
            }
            stream = stream_ssl.get();
        }
        result = mini::net::http::client::get(
            host,
            port,
            path,
            *stream);
        if (!result.is_empty())
        {
            mini_info("Response received...");
        }
        else
        {
            mini_warning("Received empty response!");
        }
        //
        // NB: if ssl_stream is wrapped around the tor_stream,
        // the ssl_stream may attempt to write into already closed
        // tor_stream upon destruction.
        //
        // i'm not sure if it should be considered as an error,
        // but it doesn't cause any problems.
        //
        return result;
    }

    mini::size_type get_hop_count(void)
    {
        return _circuit ? _circuit->get_circuit_node_list().get_size() : 0;
    }

private:
    mini::tor::consensus _consensus
#if defined (MINI_TOR_USE_CONSENSUS_CACHE)
        = mini::tor::consensus("cached-consensus")
#endif
        ;

    mini::tor::tor_socket _socket;
    mini::tor::circuit* _circuit = nullptr;
    mini::collections::list<mini::tor::onion_router*> _forbidden_onion_routers;
};


// -----------------------------------------------
//
// -----------------------------------------------
int __cdecl main()
{
    int N = 4;
    int M = 2;

    std::string address = "https://api.ipify.org";
    mini::log.set_level(mini::logger::level::info);
    static constexpr mini::size_type hops = 2;
    static_assert(hops >= 2, "There must be at least 2 hops in the circuit");
    static_assert(hops <= 9, "There must be at most 9 hops in the circuit");
    tor_client* tor = nullptr;

    // we need to get N pages 
    for (int i = 0; i < N; ++i)
    {
        // every M iterations change IP
        if (i % M == 0) 
        {
            if (tor != nullptr)
            {
                delete tor;
                tor = nullptr;
            }
            //
            // fetch the page.
            //
            mini_info("Fetching consensus...");
            tor = new tor_client();
            mini_info("Consensus fetched...");
        }

        // page parameter
        std::string page = "";
        // if (i > 0)
        // {
        //     page = "&page=" + std::to_string(i + 1);
        // }
    connect_again:
        while (tor->get_hop_count() < hops)
        {
            //
            // first hop.
            //
            if (tor->get_hop_count() == 0)
            {
                tor->extend_to_random(
                    mini::tor::onion_router::status_flag::fast |
                    mini::tor::onion_router::status_flag::running |
                    mini::tor::onion_router::status_flag::valid,
                    { 80, 443 });
            }
            //
            // last hop (exit node).
            //
            else if (tor->get_hop_count() == (hops - 1))
            {
                tor->extend_to_random(
                    mini::tor::onion_router::status_flag::fast |
                    mini::tor::onion_router::status_flag::running |
                    mini::tor::onion_router::status_flag::valid |
                    mini::tor::onion_router::status_flag::exit);
            }
            //
            // middle hops.
            //
            else
            {
                tor->extend_to_random(
                    mini::tor::onion_router::status_flag::fast |
                    mini::tor::onion_router::status_flag::running |
                    mini::tor::onion_router::status_flag::valid);
            }
        }
        mini::string content = tor->http_get(mini::net::uri((address + page).c_str()));
        if (content.is_empty())
        {
            mini_info("Trying to build new circuit...");
            goto connect_again;
        }
        mini::io::file::write_from_string("out.txt", content);
        mini::console::write("%s", content.get_buffer());
        mini_info("");
        mini_info("-----------------------------");
        mini_info("content size: %u bytes", content.get_size());
        mini_info("-----------------------------");
        process(content);
    }// for
    if (tor != nullptr)
    {
        delete tor;
        tor = nullptr;
    }
    return 0;
}

