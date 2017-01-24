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
using std::weak_ptr;
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

template<class... T> static void ignore_unused(const T&...) {}

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

    std::string name() const { return room.username(); }
};

void wait(typename Clock::duration duration, io_service& ios, function<void()> h) {
    if (duration.count() == 0) {
        return h();
    }

    auto timer = make_shared<asio::steady_timer>(ios);

    timer->expires_from_now(duration);
    timer->async_wait([h, t = timer] (error_code) { h(); });
}

//------------------------------------------------------------------------------
std::string str_impl(std::stringstream& ss) {
    return ss.str();
}

template<class Arg, class... Args>
std::string str_impl(std::stringstream& ss, Arg&& arg, Args&&... args) {
    ss << arg;
    return str_impl(ss, std::forward<Args>(args)...);
}

template<class... Args>
std::string str(Args&&... args) {
    std::stringstream ss;
    return str_impl(ss, std::forward<Args>(args)...);
}
//------------------------------------------------------------------------------
template<class Handler> void async_loop_(unsigned int i, Handler h) {
    h(i, [h, j = i + 1]() { async_loop_(j, std::move(h)); });
}

template<class Handler> void async_loop(Handler h) {
    async_loop_(0, std::move(h));
}

//------------------------------------------------------------------------------
template<class F> std::function<void()> on_nth_invocation(unsigned int n, F&& f) {
    if (n == 0) {
        f();
        return [] {};
    }

    auto counter = move_to_shared(n);

    return [=] {
        if (--*counter == 0) f();
    };
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
                    conv->wait_for_user_to_join_chat([=, c = conv](std::string name) {
                            ignore_unused(name);
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
        auto finish = on_nth_invocation(wait_for, h);

        auto delay = wait_between_invites;

        for (size_t i = 0; i < wait_for; ++i) {
            room.wait_for_user_to_join([=, &room] (std::string username, const PublicKey& pubkey) {
                wait(i * delay, room.get_io_service(), [=] {
                    conv->invite(username, pubkey);
                    conv->wait_for_user_to_join_chat([=, c = conv](std::string name) {
                            ignore_unused(name);
                            finish();
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

                    auto N = num_users - size;
                    auto count = make_shared<size_t>(N);

                    // TODO: Sometimes we get "user joined chat" event even when
                    //       that user is already in the conversation after it's
                    //       been created. Add a test for that.
                    for (size_t i = 0; i < N; ++i) {
                        conv_p->wait_for_user_to_join_chat([=, &room](std::string) {
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
std::function<void()> create_session(io_service& ios,
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

    std::list<shared_ptr<Room>> rooms;

    for (size_t i = 0; i < client_count; ++i) {
        auto r = make_shared<Room>(ios, str("user", i));

        rooms.push_back(r);
        //r->enable_message_logging();

        r->connect(server_ep, [=] (error_code ec) {
            BOOST_CHECK(!ec);

            weak_ptr<Room> w = r;

            if (i == 0) {
                create_conv_and_wait(*r, client_count, invite_strategy, [=] (Conv conv) {
                        if (auto r = w.lock()) {
                            on_one_client_done(move(*r), move(conv));
                        }
                    });
            }
            else {
                wait_for_invite_and_users(*r, client_count, [=] (Conv conv) {
                        if (auto r = w.lock()) {
                            on_one_client_done(move(*r), move(conv));
                        }
                    });
            }
        });
    }

    return [rooms = move(rooms), result] {
        for (auto& room : rooms) {
            if (room->has_impl()) { room->stop(); }
        }
        result->clear();
    };
}

//------------------------------------------------------------------------------
template<class InviteStrategy>
void test_create_session(size_t user_count,
                         InviteStrategy invite_strategy,
                         Clock::duration kill_duration = 0s) {
    io_service ios;

    EchoServer server(ios);

    bool callback_called = false;

    asio::steady_timer timer(ios);

    auto cancel =
        create_session(ios, user_count, server.local_endpoint(), invite_strategy,
            [&] (std::vector<User> users) {
                BOOST_CHECK_EQUAL(users.size(), user_count);

                callback_called = true;
                server.stop();
                timer.cancel();

                /*
                 * TODO: ATM Rooms can't be destroyed inside on receive handlers.
                 *       https://github.com/equalitie/np1sec/issues/44
                 */
                ios.post([us = move_to_shared(users)] {});
            });

    if (kill_duration.count()) {
        timer.expires_from_now(kill_duration);
        timer.async_wait([cancel = move(cancel), &server] (auto error) {
            if (error) return;
            cancel();
            server.stop();
        });
    }

    ios.run();

    BOOST_CHECK(callback_called);
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(invite_consecutive_size_2)
{
    test_create_session(2, ConsecutiveInviteStrategy{0s});
}

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

BOOST_AUTO_TEST_CASE(invite_concurrent_size_6_delay_3s)
{
    test_create_session(6, ConcurrentInviteStrategy{3s}, 60s);
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_4_delay_100ms)
{
    test_create_session(4, ConcurrentInviteStrategy{100ms}, 30s);
}

BOOST_AUTO_TEST_CASE(invite_concurrent_size_3_delay_0ms)
{
    test_create_session(3, ConcurrentInviteStrategy{0ms}, 10s);
}

//------------------------------------------------------------------------------
template<class H> void test_with_session(size_t user_count, H&& h) {
    using Users = std::vector<User>;

    io_service ios;

    EchoServer server(ios);

    bool callback_called = false;

    ConsecutiveInviteStrategy invite_strategy{0s};

    Users users;

    auto finish = [&] (){
        callback_called = true;
        server.stop();

        /*
         * TODO: ATM Rooms can't be destroyed inside on receive handlers.
         *       https://github.com/equalitie/np1sec/issues/44
         */
        ios.post([&] { users.clear(); });
    };

    auto cancel = create_session(ios, user_count, server.local_endpoint(), invite_strategy,
            [&] (Users new_users) {
                BOOST_CHECK_EQUAL(new_users.size(), user_count);
                users = move(new_users);
                h(server, users, finish);
            });

    ios.run();

    BOOST_CHECK(callback_called);
}

template<class H> void test_with_session_each_user(size_t user_count, H&& h) {
    using Users = std::vector<User>;

    test_with_session(user_count, [=] (EchoServer&, Users& users, auto finish) {
        auto on_finish_one = on_nth_invocation(users.size(), [=] {
            finish();
        });

        for (auto& user : users) {
            h(user, on_finish_one);
        }
    });
}

//------------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(test_consecutive_message_exchange)
{
    const size_t user_count = 10;
    const size_t message_count = 30;

    test_with_session_each_user(user_count, [=] (User& user, auto finish) {
        struct State {
            bool do_send = true;
            size_t next_msg_id = 0;
        };

        auto state = make_shared<State>();

        async_loop([=, &user] (unsigned int i, auto cont) {
            const size_t total_to_receive = user_count * message_count;

            if (i == total_to_receive) {
                return finish();
            }

            if (state->do_send) {
                user.conv.send_chat(str("Message #", state->next_msg_id++));
            }

            user.conv.receive_chat([=, &user] (const std::string& source, const std::string& msg) {
                ignore_unused(msg);
                //cout << i << "/" << total_to_receive
                //    << " User " << user.name()
                //    << " received \"" << msg
                //    << "\" from " << source << endl;

                state->do_send = source == user.name();
                return cont();
            });
        });
    });
}
//------------------------------------------------------------------------------

struct RandomDuration {
    std::random_device rd;
    std::mt19937 gen;
    std::normal_distribution<> distribution;

    RandomDuration(Clock::duration mean, Clock::duration variance)
        : gen(rd()), distribution(mean.count(), variance.count()) {}

    Clock::duration get() {
        using namespace std;
        return Clock::duration(max<int>(0, round(distribution(gen))));
    }
};

BOOST_AUTO_TEST_CASE(test_randomized_message_exchange)
{
    const size_t user_count = 10;
    const size_t message_count = 30;

    auto random_duration = make_shared<RandomDuration>(20ms, 10ms);

    test_with_session_each_user(user_count, [=] (User& user, auto finish) {
        auto next_msg_id = make_shared<size_t>(0);

        auto one_loop_finished = on_nth_invocation(2, [=] {
            finish();
        });

        async_loop([=, &user] (unsigned int i, auto cont) {
            if (i == message_count) {
                return one_loop_finished();
            }

            user.conv.send_chat(str("Message #", (*next_msg_id)++));

            wait(random_duration->get(), user.room.get_io_service(), [=] {
                cont();
            });
        });

        async_loop([=, &user] (unsigned int i, auto cont) {
            const size_t total_to_receive = user_count * message_count;

            if (i == total_to_receive) {
                return one_loop_finished();
            }

            user.conv.receive_chat([=, &user] (const std::string& source, const std::string& msg) {
                ignore_unused(source, msg);
                //cout << i << "/" << total_to_receive
                //    << " User " << user.name()
                //    << " received \"" << msg
                //    << "\" from " << source << endl;

                return cont();
            });
        });
    });
}
//------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_ddos_hello)
{
    io_service ios;

    std::vector<Room> rs;

    constexpr size_t N = 20;

    for (unsigned int i = 0; i < N; ++i) {
        rs.emplace_back(ios, str("alice", i));
    }

    EchoServer server(ios);

    auto server_ep = server.local_endpoint();

    bool stop_mallory = false;

    // Mallory starts to connect to the server as often as possible.
    async_loop([&] (unsigned int i, auto continue_loop) {
        auto mallory = make_shared<Room>(ios, str("mallory", i));

        mallory->connect(server_ep, [=, m = mallory, &stop_mallory] (auto ec) {
            if (stop_mallory) return;
            BOOST_CHECK(!ec);
            continue_loop();
        });
    });

    auto has_all_alices = [] (const Room& room) {
        // TODO: This could be done more efficiently.
        for (unsigned int i = 0; i < N; ++i) {
            auto alice = str("alice", i);
            if (room.users().count(alice) == 0 && room.username() != alice) {
                return false;
            }
        }
        return true;
    };

    auto finish = on_nth_invocation(N, [&] {
        for (auto& r : rs) {
            r.stop();
        }
        server.stop();
        stop_mallory = true;
    });

    for (size_t i = 0; i < rs.size(); ++i) {
        auto& r = rs[i];

        wait(i * 10ms, ios, [&] {
            r.connect(server_ep, [&] (auto ec) {
                BOOST_CHECK(!ec);

                async_loop([&](unsigned int, auto continue_waiting) {
                    r.wait_for_user_to_join([=, &r] (std::string, const auto&) {
                        if (has_all_alices(r)) {
                            return finish();
                        }
                        continue_waiting();
                    });
                });
            });
        });
    }

    ios.run();
}

//------------------------------------------------------------------------------
void test_message_dropping(np1sec::Message::Type message_type_to_drop)
{
    using Users = std::vector<User>;

    constexpr size_t orig_session_count = 4;

    auto join_new_guy = [=] (EchoServer& server, auto h) {
        auto room = make_shared<Room>(server.get_io_service(), "new_guy");
        room->get_np1sec_room()->debug_disable_fsck();
        //room->enable_message_logging();

        room->connect(server.local_endpoint(), [=] (error_code ec) {
            BOOST_CHECK(!ec);

            room->wait_for_invite([=] (Conv conv) {
                auto conv_p = move_to_shared(conv);

                conv_p->join([=] {
                    conv_p->wait_until_joined_chat([=] {
                         h(User{move(*room), move(*conv_p)});
                    });
                });
            });
        });
    };

    test_with_session(orig_session_count, [&] (EchoServer& server, Users& users, auto finish) {
        BOOST_CHECK_EQUAL(users.size(), orig_session_count);

        /* Match indices with usernames (user with index 0 shall have name "user0",...) */
        std::sort(users.begin(), users.end(),
                  [](const User& a, const User& b)
                  { return a.name() < b.name(); });

        const size_t inviter_i = 0;
        const size_t mallory_i = 1; // The mallicious user

        auto& ios = server.get_io_service();
        auto& inviter = users[inviter_i];
        auto& mallory = users[mallory_i];

        /* Mallory won't respond to messages of certain type from the new_guy */
        mallory.room.set_inbound_message_filter(
                [=](const std::string& sender, const np1sec::Message& msg) {
            if (sender == "new_guy" && msg.type == message_type_to_drop) {
                return false;
            }
            return true;
        });

        auto on_finish_one = on_nth_invocation(2*(users.size() - 1) + (1), [=] {
            finish();
        });

        inviter.room.wait_for_user_to_join([=, &users, &ios] (std::string username, PublicKey pubkey) {
            BOOST_REQUIRE(username == "new_guy");

            auto& inviter = users[inviter_i];

            inviter.conv.invite(username, pubkey);

            for (size_t i = 0; i < users.size(); ++i) {
                auto& user = users[i];

                user.room.get_np1sec_room()->debug_disable_fsck();

                if (i == mallory_i || user.name() == "new_guy") continue;

                auto name = user.name();

                /* Wait for the new guy to join chat */
                user.conv.wait_for_user_to_join_chat([=, &ios](std::string new_guy) {
                    BOOST_REQUIRE(new_guy == "new_guy");
                    ios.post(on_finish_one);
                });

                /* Wait for Mallory to leave */
                user.conv.wait_for_user_to_leave([=, &ios, &users](std::string username) {
                    BOOST_REQUIRE(username == users[mallory_i].name());
                    ios.post(on_finish_one);
                });
            }
        });

        join_new_guy(server, [=, &ios, &users](User user) {
            users.push_back(move(user));
            ios.post(on_finish_one);
        });
    });
}

BOOST_AUTO_TEST_CASE(test_drop_message_Join)
{
    test_message_dropping(np1sec::Message::Type::Join);
}

BOOST_AUTO_TEST_CASE(test_drop_message_KeyExchangePublicKey)
{
    test_message_dropping(np1sec::Message::Type::KeyExchangePublicKey);
}

BOOST_AUTO_TEST_CASE(test_drop_message_KeyExchangeSecretShare)
{
    test_message_dropping(np1sec::Message::Type::KeyExchangeSecretShare);
}

BOOST_AUTO_TEST_CASE(test_drop_message_Acceptance)
{
    test_message_dropping(np1sec::Message::Type::KeyExchangeAcceptance);
}

BOOST_AUTO_TEST_CASE(test_drop_message_KeyActivation)
{
    test_message_dropping(np1sec::Message::Type::KeyActivation);
}

//------------------------------------------------------------------------------
