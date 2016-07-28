/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
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
/**
 * This file should be included by the client to use develop the interface
 * between np1sec and the client.
 *
 * See test/chat_mocker_np1sec_plugin.h/.cc  example
 */

#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_

#include <cassert>
#include <string>
#include <vector>

#include "timer.h"

namespace np1sec
{

class Application
{
    public:
    virtual uint32_t heartbeat_interval() const = 0;
    virtual uint32_t session_life_span() const = 0;
    virtual uint32_t inactive_ergo_non_sum_interval() const = 0;
    virtual uint32_t unresponsive_ergo_non_sum_interval() const = 0;
    virtual uint32_t ack_interval() const = 0;
    virtual uint32_t consistency_failure_interval() const = 0;
    virtual uint32_t send_receive_interval() const = 0;

    virtual void send_message(std::string room, std::string message) = 0;

    virtual void join(std::string room, std::vector<std::string> plist) = 0;

    virtual void leave(std::string room, std::vector<std::string> plist) = 0;

    virtual void display_message(std::string room, std::string nickname, std::string message) = 0;

    protected:
    virtual Timer do_set_timer(uint32_t interval, Timer::Callback* callback) = 0;

    public:
    template<class CallbackType> Timer set_timer(uint32_t interval, const CallbackType& callback)
    {
        struct Callback : public Timer::Callback
        {
            CallbackType callback;

            Callback(const CallbackType& callback):
                callback(callback)
            {}

            void call()
            {
                callback();
            }
        };

        Callback* timer_callback = new Callback(callback);
        return do_set_timer(interval, timer_callback);
    }
};

template<class TimerTokenType>
class TemplateApplication : public Application
{
    protected:
    virtual TimerTokenType set_timer(uint32_t interval, Timer::Body* timer) = 0;
    virtual void unset_timer(const TimerTokenType& timer) = 0;

    Timer do_set_timer(uint32_t interval, Timer::Callback* callback)
    {
        struct Token : public Timer::Token
        {
            TemplateApplication* application;
            TimerTokenType token;

            void unset()
            {
                application->unset_timer(token);
            }
        };

        Timer timer;
        timer.set(callback);

        Token* token = new Token;
        token->application = this;
        token->token = set_timer(interval, timer.body());

        if (timer.active()) {
            timer.set_token(token);
        } else {
            // timer was called during set_timer()
            delete token;
        }

        return timer;
    }
};

/*
 * The AppOps defined below is a legacy API that will be replaced at some point.
 * A variant of this can be implemented later as a C api.
 */
typedef void (*timeout_callback)(void*);

struct AppOps
{
    // Data that is passed to send_bare
    uint32_t c_heartbeating_interval;
    uint32_t c_session_life_span;
    uint32_t c_inactive_ergo_non_sum_interval;
    uint32_t c_unresponsive_ergo_non_sum_interval;
    uint32_t c_ack_interval;
    uint32_t c_consistency_failure_interval;
    uint32_t c_send_receive_interval;

    AppOps(){};

    AppOps(uint32_t ACK_GRACE_INTERVAL, uint32_t REKEY_GRACE_INTERVAL, uint32_t INTERACTION_GRACE_INTERVAL,
                 uint32_t BROADCAST_LATENCY)
        : c_heartbeating_interval(REKEY_GRACE_INTERVAL / 2 + 2 * (BROADCAST_LATENCY)),
          c_session_life_span(REKEY_GRACE_INTERVAL + 2 * (BROADCAST_LATENCY)),
          c_unresponsive_ergo_non_sum_interval(INTERACTION_GRACE_INTERVAL + 2 * (BROADCAST_LATENCY)),
          c_ack_interval(ACK_GRACE_INTERVAL),
          c_consistency_failure_interval(ACK_GRACE_INTERVAL + 2 * (BROADCAST_LATENCY)),
          c_send_receive_interval(INTERACTION_GRACE_INTERVAL + 2 * (BROADCAST_LATENCY))
    {
    }

    void* bare_sender_data = NULL;
    /**
     * It is called by np1sec whenever the protocol needs to send meta data
     * messages (key exchange, etc) which are not initiated by a message from
     * the user.
     *
     * @param data is member variable bare_sender_data which is passed to the
     *             function in case any auxilary data is needed
     *
     *
     */
    void (*send_bare)(std::string room_name, std::string message, void* data);

    // TODO(vmon): Why do we need to join a room?
    // We can call back when join or leave is completed but
    // then also we need a call back when other people
    // join the room or leave that's why we have room
    // action as the return of the receive handlere

    // The problem is that some of the actions are
    // not message dependent like fail to ping for example.

    /**
     * inform the app that someone (including the user themselves)
     * join a room or a coversation left the room.
     */
    void (*join)(std::string room_name,
                 // std::string joiner_nickname,
                 std::vector<std::string> plist, void* aux_data);

    /**
     * inform the app that someone (including the user themself) left
     a room or a coversation, for other p ui purpose
     */
    void (*leave)(std::string room_name, std::vector<std::string> plist, void* aux_data);

    /**
     * Asks the app to display a message in the room
     */
    void (*display_message)(std::string room_name, std::string sender_nick, std::string message, void* aux_data);

    /**
     * it needs to set a timer which calls timer_callback function after
     * interval
     *
     * @return a handle to the timer as void* which can be sent to axe_timer
     *         to delete the timer
     */
    void* (*set_timer)(void (*timer_callback)(void* opdata), void* opdata, uint32_t interval, void* data);

    /**
     * should deactiave to_be_defused timer
     */
    void (*axe_timer)(void* to_be_defused_timer, void* data);
};

class AppOpsApplication : public TemplateApplication<void *>
{
    protected:
    public:
    AppOps *ops;

    public:
    AppOpsApplication(AppOps *ops): ops(ops) {}

    uint32_t heartbeat_interval() const { return ops->c_heartbeating_interval; }
    uint32_t session_life_span() const { return ops->c_session_life_span; }
    uint32_t inactive_ergo_non_sum_interval() const { return ops->c_inactive_ergo_non_sum_interval; }
    uint32_t unresponsive_ergo_non_sum_interval() const { return ops->c_unresponsive_ergo_non_sum_interval; }
    uint32_t ack_interval() const { return ops->c_ack_interval; }
    uint32_t consistency_failure_interval() const { return ops->c_consistency_failure_interval; }
    uint32_t send_receive_interval() const { return ops->c_send_receive_interval; }

    void send_message(std::string room, std::string message)
    {
        ops->send_bare(room, message, ops->bare_sender_data);
    }

    void join(std::string room, std::vector<std::string> plist)
    {
        ops->join(room, plist, ops->bare_sender_data);
    }

    void leave(std::string room, std::vector<std::string> plist)
    {
        ops->leave(room, plist, ops->bare_sender_data);
    }

    void display_message(std::string room, std::string nickname, std::string message)
    {
        ops->display_message(room, nickname, message, ops->bare_sender_data);
    }

    protected:
    static void call_timer(void *data)
    {
        Timer::Body* timer = static_cast<Timer::Body*>(data);
        timer->trigger();
    }

    void* set_timer(uint32_t interval, Timer::Body* callback)
    {
        return ops->set_timer(call_timer, callback, interval, ops->bare_sender_data);
    }

    void unset_timer(void* const& timer)
    {
        ops->axe_timer(timer, ops->bare_sender_data);
    }
};

} // namespace np1sec

#endif // SRC_INTERFACE_H_
