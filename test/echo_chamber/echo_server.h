/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <queue>
#include <set>
#include <boost/asio.hpp>
#include <boost/range/adaptor/map.hpp>

constexpr size_t MAX_MESSAGE_SIZE = 4096;

struct EchoServerImpl : public std::enable_shared_from_this<EchoServerImpl> {
    using tcp = boost::asio::ip::tcp;

    struct Connection {
        struct TxBuffers {
            uint32_t size;
            std::vector<uint8_t> data;
        };

        uint32_t rx_size_buffer;
        std::vector<uint8_t> rx_buffer;
        std::queue<TxBuffers> tx_buffers;
        tcp::socket socket;
        
        Connection(tcp::socket s)
            : rx_buffer(MAX_MESSAGE_SIZE)
            , socket(std::move(s)) {}
    };
    
    bool stopped = false;
    tcp::acceptor acceptor;
    std::set<std::shared_ptr<Connection>> connections;

    EchoServerImpl(boost::asio::io_service& ios, uint16_t port);

    void start_accepting();
    void stop();
    void register_socket(tcp::socket);
    void start_reading(const std::shared_ptr<Connection>&);
    void broadcast(std::vector<uint8_t>);
    void send_head(const std::shared_ptr<Connection>& c);
    void send(const std::shared_ptr<Connection>& c, const std::vector<uint8_t>& data);
};

inline
EchoServerImpl::EchoServerImpl(boost::asio::io_service& ios, uint16_t port)
    : acceptor(ios, tcp::endpoint(tcp::v4(), port))
{
}

inline void EchoServerImpl::stop()
{
    if (stopped) return;
    stopped = true;
    acceptor.close();
    for (auto& c : connections) {
        c->socket.close();
    }
}

inline
void EchoServerImpl::start_accepting()
{
    auto socket = std::make_shared<tcp::socket>(acceptor.get_io_service());
    
    acceptor.async_accept(*socket,
            [this, socket, self = shared_from_this()]
            (const boost::system::error_code& ec) {
                if (ec || stopped) {
                    return;
                }
                register_socket(std::move(*socket));
                start_accepting();
            });
}

inline
void EchoServerImpl::start_reading(const std::shared_ptr<Connection>& c)
{
    namespace asio = boost::asio;
    using error_code = boost::system::error_code;
    
    asio::mutable_buffers_1 buf(&c->rx_size_buffer, sizeof(c->rx_size_buffer));

    asio::async_read(c->socket, buf,
            [this, c, self = shared_from_this()]
            (error_code ec, size_t) {
                if (ec || stopped) {
                    connections.erase(c);
                    return;
                }

                asio::mutable_buffers_1 buf(c->rx_buffer.data(), c->rx_size_buffer);

                asio::async_read(c->socket, buf,
                        [this, c, self = std::move(self)]
                        (boost::system::error_code ec, size_t size) {
                           if (ec || stopped) {
                               connections.erase(c);
                               return;
                           }
                           broadcast(std::vector<uint8_t>( c->rx_buffer.begin()
                                                         , c->rx_buffer.begin() + size));
                           start_reading(c);
                        });
            });
}

inline
void EchoServerImpl::send_head(const std::shared_ptr<Connection>& c)
{
    namespace asio = boost::asio;
    
    assert(!c->tx_buffers.empty());

    auto& front = c->tx_buffers.front();

    std::array<asio::const_buffer, 2> buffs =
        { asio::const_buffer(&front.size, sizeof(front.size))
        , asio::const_buffer(front.data.data(), front.data.size()) };

    boost::asio::async_write(c->socket, buffs,
            [this, c, self = shared_from_this()]
            (boost::system::error_code ec, size_t) {
                c->tx_buffers.pop();

                if (ec || stopped) {
                    connections.erase(c);
                    return;
                }

                if (!c->tx_buffers.empty()) send_head(c);
            });
}

inline
void EchoServerImpl::send(const std::shared_ptr<Connection>& c, const std::vector<uint8_t>& data)
{
    bool is_sending = !c->tx_buffers.empty();
    
    c->tx_buffers.push(Connection::TxBuffers{uint32_t(data.size()), data});
    
    if (is_sending) return;
    
    send_head(c);
}

inline
void EchoServerImpl::broadcast(std::vector<uint8_t> data)
{
    for (auto& c : connections) {
        send(c, data);
    }
}

inline
void EchoServerImpl::register_socket(tcp::socket socket)
{
    auto c = std::make_shared<Connection>(std::move(socket));
    connections.emplace(c);
    start_reading(c);
}

class EchoServer {
    using tcp = boost::asio::ip::tcp;

public:
    EchoServer(boost::asio::io_service& ios, uint16_t port = 0)
        : _impl(std::make_shared<EchoServerImpl>(ios, port))
    {
        _impl->start_accepting();
    }

    EchoServer(const EchoServer&) = delete;
    EchoServer& operator=(const EchoServer&) = delete;

    EchoServer(EchoServer&&) = default;
    EchoServer& operator=(EchoServer&&) = default;

    ~EchoServer()
    {
        if (_impl) _impl->stop();
    }
    
    void stop() {
        _impl->stop();
    }

    tcp::endpoint local_endpoint() const {
        return _impl->acceptor.local_endpoint();
    }

private:
    std::shared_ptr<EchoServerImpl> _impl;
};

