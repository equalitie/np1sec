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

#include "pipe.h"

struct ConvImpl : public std::enable_shared_from_this<ConvImpl>
                , public np1sec::ConversationInterface {

    ConvImpl(np1sec::Conversation* np1sec_conv)
        : np1sec_conv(np1sec_conv)
    {}

    void user_invited(const std::string&, const std::string&) override {}
    void invitation_cancelled(const std::string&, const std::string&) override {}
    void user_authenticated(const std::string&, const np1sec::PublicKey&) override {}
    void user_authentication_failed(const std::string&) override {}
    void user_joined(const std::string&) override {}
    void user_left(const std::string&) override {}
    void votekick_registered(const std::string&, const std::string&, bool) override {}

    void user_joined_chat(const std::string& username) override {
        user_joined_chat_pipe.apply(username);
    }

    void message_received(const std::string& sender, const std::string& message) override {
        chat_pipe.apply(sender, message);
    }

    void joined() override {
        join_pipe.apply();
    }

    void joined_chat() override {
        joined_chat_pipe.apply();
    }

    void left() override {}

    ~ConvImpl() {
        np1sec_conv->leave(false);
    }

    np1sec::Conversation* np1sec_conv;
    Pipe<> join_pipe;
    Pipe<> joined_chat_pipe;
    Pipe<std::string> user_joined_chat_pipe;
    Pipe<std::string, std::string> chat_pipe;
    std::function<void()> on_joined;
};

class Conv {
public:
    Conv(boost::asio::io_service& ios, np1sec::Conversation* c)
        : _ios(&ios), _impl(std::make_shared<ConvImpl>(c))
    {}

    Conv(const Conv&) = delete;
    Conv& operator=(const Conv&) = delete;

    Conv(Conv&&) = default;
    Conv& operator=(Conv&& other) = default;

    ConvImpl* get_impl() { return _impl.get(); }
    np1sec::Conversation* get_np1sec_conv() { return _impl->np1sec_conv; }

    void invite(const std::string& user, const np1sec::PublicKey& pubkey)
    {
        _impl->np1sec_conv->invite(user, pubkey);
    }

    template<class H>
    void join(H&& h)
    {
        _impl->join_pipe.schedule(*_ios, std::forward<H>(h));
        _impl->np1sec_conv->join();
    }

    template<class H>
    void wait_until_joined_chat(H&& h)
    {
        _impl->joined_chat_pipe.schedule(*_ios, std::forward<H>(h));
    }

    template<class H>
    void wait_for_user_to_join_chat(H&& h)
    {
        _impl->user_joined_chat_pipe.schedule(*_ios, std::forward<H>(h));
    }

    template<class H>
    void receive_chat(H&& h) {
        _impl->chat_pipe.schedule(*_ios, std::forward<H>(h));
    }

    void send_chat(const std::string& m) {
        _impl->np1sec_conv->send_chat(m);
    }

private:
    boost::asio::io_service* _ios;
    std::shared_ptr<ConvImpl> _impl;
};


