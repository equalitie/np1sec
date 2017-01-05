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

#include "echo_server.h"

class Client : public std::enable_shared_from_this<Client> {
    using tcp = boost::asio::ip::tcp;
    using error_code = boost::system::error_code;

    using OnMessageReceived =
        std::function<void(const std::string&, const std::string&)>;

public:
    Client(boost::asio::io_service& ios, OnMessageReceived on_recv)
        : _socket(ios)
        , _rx_payload_buffer(MAX_MESSAGE_SIZE)
        , _on_message_received(std::move(on_recv))
    {}

    void stop() {
        if (_stopped) return;
        _stopped = true;
        _socket.close();
    }

    void connect(tcp::endpoint remote_ep, std::function<void(error_code)> h)
    {
        _socket.async_connect(remote_ep,
                [this, h = std::move(h), self = shared_from_this()]
                (boost::system::error_code ec) {
                    namespace error = boost::asio::error;
                    if (_stopped) return h(error::operation_aborted);
                    if (ec) return h(ec);
                    start_receiving();
                    h(ec);
                });
    }

    boost::asio::io_service& get_io_service() {
        return _socket.get_io_service();
    }

    void send_message(const std::string& name, const std::string& msg)
    {
        bool is_sending = !_tx_queue.empty();
        _tx_queue.push(name + ';' + msg);
        assert(_tx_queue.back().size() <= MAX_MESSAGE_SIZE);
        if (!is_sending) send_head();
    }

private:
    void start_receiving() {
        namespace asio = boost::asio;
        using error_code = boost::system::error_code;

        asio::async_read(_socket
                , asio::buffer(&_rx_size_buffer, sizeof(_rx_size_buffer))
                , [this, self = shared_from_this()](error_code ec, size_t) {
                      if (ec || _stopped) return;
                      asio::async_read(_socket
                              , asio::buffer(_rx_payload_buffer.data(), _rx_size_buffer)
                              , [this, self] (error_code ec, size_t) {
                                    if (ec || _stopped) return;
                                    on_message_received();
                                    if (!_stopped) start_receiving();
                                });
                  });
    }

    void on_message_received() {
        assert(_rx_size_buffer <= _rx_payload_buffer.size());

        std::string msg( _rx_payload_buffer.begin()
                       , _rx_payload_buffer.begin() + _rx_size_buffer);

        auto separator = msg.find(';');
        assert(separator != std::string::npos);

        _on_message_received( msg.substr(0, separator)
                            , msg.substr(separator + 1));
    }

    void send_head()
    {
        assert(!_tx_queue.empty());
        using namespace boost;

        auto& msg = _tx_queue.front();
        _tx_size_buffer = msg.size();
        _tx_payload_buffer = std::vector<uint8_t>(msg.begin(), msg.end());

        std::array<asio::const_buffer, 2> buffers =
            { asio::const_buffer(&_tx_size_buffer, sizeof(_tx_size_buffer) )
            , asio::const_buffer(_tx_payload_buffer.data(), _tx_payload_buffer.size() )
            };

        asio::async_write(_socket, buffers,
                [this, self = shared_from_this()](system::error_code ec, size_t) {
                    _tx_queue.pop();
                    if (ec || _stopped) return;
                    if (!_tx_queue.empty()) send_head();
                });
    }

private:
    bool _stopped = false;
    tcp::socket _socket;
    uint32_t _tx_size_buffer;
    std::vector<uint8_t> _tx_payload_buffer;
    std::queue<std::string> _tx_queue;

    uint32_t _rx_size_buffer;
    std::vector<uint8_t> _rx_payload_buffer;
    OnMessageReceived _on_message_received;
};
