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

#define BOOST_TEST_MODULE EchoChamber
#include <boost/test/unit_test.hpp>

#include <iostream>
#include <chrono>
#include "echo_server.h"
#include "room.h"

using error_code = boost::system::error_code;
using std::move;
using std::shared_ptr;
using std::unique_ptr;
using std::make_shared;
using std::make_unique;
using std::cout;
using std::endl;
using boost::asio::io_service;
using tcp = boost::asio::ip::tcp;
using np1sec::PublicKey;
namespace asio = boost::asio;
using namespace std::chrono_literals;
using std::function;
using Clock = std::chrono::steady_clock;

template<class T>
shared_ptr<T> move_to_shared(T& arg) {
    return std::make_shared<T>(std::move(arg));
}

struct User {
    Room room;
    Conv conv;

    User(User&& other) = default;
    User& operator=(User&&) = default;
    User(const User&) = delete;
    User& operator=(const User&) = delete;
};

static std::string user_name(size_t i) {
    std::stringstream ss;
    ss << "user" << i;
    return ss.str();
}

void wait(typename Clock::duration duration, io_service& ios, function<void()> h) {
    if (duration.count() == 0) {
        return h();
    }

    auto timer = make_shared<asio::steady_timer>(ios);

    timer->expires_from_now(duration);
    timer->async_wait([h, t = timer] (error_code) { h(); });
}

//------------------------------------------------------------------------------
template<class Handler> void async_loop_(unsigned int i, Handler h) {
    h(i, [h, j = i + 1]() { async_loop_(j, std::move(h)); });
}

template<class Handler> void async_loop(Handler h) {
    async_loop_(0, std::move(h));
}

//------------------------------------------------------------------------------
struct ConsecutiveInviteStrategy {
    Clock::duration wait_between_invites;

    void run(Room& room, shared_ptr<Conv> conv, size_t wait_for, std::function<void()> h) const {
        auto in_chat_counter = make_shared<size_t>(wait_for);

        async_loop([=, &room, delay = wait_between_invites] (unsigned int i, auto cont) {
            if (i == wait_for) {
                return h();
            }

            room.wait_for_user_to_join([=, &room] (std::string username, const PublicKey& pubkey) {
                wait(delay, room.get_io_service(), [=] {
                    conv->invite(username, pubkey);
                    conv->wait_for_user_to_join_chat([=, c = conv](std::string) {
                            cont();
                        });
                });
            });
        });
    }
};

struct ConcurrentInviteStrategy {
    Clock::duration wait_between_invites;

    void run(Room& room, shared_ptr<Conv> conv, size_t wait_for, std::function<void()> h) const {
        auto in_chat_counter = make_shared<size_t>(wait_for);

        auto delay = wait_between_invites;

        for (size_t i = 0; i < wait_for; ++i) {
            room.wait_for_user_to_join([=, &room] (std::string username, const PublicKey& pubkey) {
                wait(i * delay, room.get_io_service(), [=] {
                    conv->invite(username, pubkey);
                    conv->wait_for_user_to_join_chat([=, c = conv](std::string) {
                            if (--*in_chat_counter == 0) {
                                h();
                            }
                        });
                });
            });
        }
    }
};

//------------------------------------------------------------------------------
/*
 * Create conversation, then wait until there is num_users user in it.
 */
template<class InviteStrategy>
void create_conv_and_wait(Room& room, size_t num_users, InviteStrategy invite_strategy, function<void(Conv)> h)
{
    auto& ios = room.get_io_service();

    assert(num_users > 0);

    room.create_conversation([=, &room, &ios](Conv conv) {
        auto conv_p = move_to_shared(conv);
    
        if (num_users == 1) {
            return ios.post([h, conv_p] { h(move(*conv_p)); });
        }

        invite_strategy.run(room, conv_p, num_users - 1, [=] {
                    h(move(*conv_p));
                });
    });
}

//------------------------------------------------------------------------------
/*
 * First wait for invitation, then join the room and then wait till there
 * is num_users users in it.
 */
void wait_for_invite_and_users(Room& room, size_t num_users, function<void(Conv)> h)
{
    room.wait_for_invite([=, &room] (Conv conv) {
        auto conv_p = move_to_shared(conv);

        conv_p->join([=, &room] {
            conv_p->wait_until_joined_chat([=, &room] {
                    auto size = conv_p->get_np1sec_conv()->participants().size();

                    assert(size <= num_users);

                    if (size == num_users) {
                        return h(move(*conv_p));
                    }

                    auto count = make_shared<size_t>(num_users - size);

                    for (size_t i = 0; i < num_users - size; ++i) {
                        conv_p->wait_for_user_to_join_chat([=](std::string) {
                            if (--*count == 0) {
                                h(move(*conv_p));
                            }
                        });
                    }
                });
        });
    });
}

//------------------------------------------------------------------------------
template<class InviteStrategy>
void create_session(io_service& ios,
                    size_t client_count,
                    tcp::endpoint server_ep,
                    InviteStrategy invite_strategy,
                    std::function<void(std::vector<User>)>&& handler)
{
    auto result = make_shared<std::vector<User>>();

    auto on_one_client_done = [=](Room room, Conv conv) {
        result->push_back(User{move(room), move(conv)});

        if (result->size() == client_count) {
            handler(std::move(*result));
        }
    };

    for (size_t i = 0; i < client_count; ++i) {
        auto r = make_shared<Room>(ios, user_name(i));

        r->connect(server_ep, [=] (error_code ec) {
            BOOST_CHECK(!ec);

            if (i == 0) {
                create_conv_and_wait(*r, client_count, invite_strategy, [=] (Conv conv) {
                        on_one_client_done(move(*r), move(conv));
                    });
            }
            else {
                wait_for_invite_and_users(*r, client_count, [=] (Conv conv) {
                        on_one_client_done(move(*r), move(conv));
                    });
            }
        });
    }
}

//------------------------------------------------------------------------------
template<class InviteStrategy>
void test_create_session(size_t user_count, InviteStrategy invite_strategy) {
    io_service ios;

    EchoServer server(ios);

    bool callback_called = false;

    create_session(ios, user_count, server.local_endpoint(), invite_strategy,
            [&] (std::vector<User> users) {
                BOOST_CHECK_EQUAL(users.size(), user_count);

                callback_called = true;
                server.stop();

                /*
                 * TODO: ATM Rooms can't be destroyed inside on receive handlers.
                 *       https://github.com/equalitie/np1sec/issues/44
                 */
                ios.post([us = move_to_shared(users)] {});
            });

    ios.run();

    BOOST_CHECK(callback_called);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(invite_consecutive_size_3)
{
    test_create_session(3, ConsecutiveInviteStrategy{0s});
}

BOOST_AUTO_TEST_CASE(invite_consecutive_size_4)
{
    test_create_session(4, ConsecutiveInviteStrategy{0s});
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_3_delay_1s)
{
    test_create_session(3, ConcurrentInviteStrategy{1s});
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_4_delay_1s)
{
    test_create_session(4, ConcurrentInviteStrategy{1s});
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_3_delay_100ms)
{
    test_create_session(3, ConcurrentInviteStrategy{100ms});
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_3_delay_0ms)
{
    test_create_session(3, ConcurrentInviteStrategy{0ms});
}

//------------------------------------------------------------------------------
