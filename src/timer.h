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

#ifndef SRC_TIMER_H_
#define SRC_TIMER_H_

#include <cassert>
#include <utility>

namespace np1sec
{

/*
 * A timer needs a consistent memory location for the callback to work properly;
 * yet we still want it to have move and destruction semantics that take care of cleanup.
 * So, a Timer contains a pointer to a Timer::Body which points back to the Timer,
 * and the move constructors and destructor ensure that a single movable Timer
 * corresponds with an immobile Timer::Body.
 */
class Timer
{
    public:
    struct Callback
    {
        virtual void call() = 0;
        virtual ~Callback() {}
    };

    struct Token
    {
        virtual void unset() = 0;
        virtual ~Token() {}
    };

    struct Body
    {
        protected:
        Callback* callback;
        Token* token;
        Timer* timer;

        public:
        void trigger()
        {
            timer->trigger();
        }

        friend class Timer;
    };

    protected:
    Body* m_body;

    void trigger()
    {
        assert(m_body);
        assert(m_body->timer == this);
        assert(m_body->callback);
        if (m_body->token) {
            delete m_body->token;
        }
        Callback* callback = m_body->callback;
        delete m_body;
        m_body = nullptr;
        callback->call();
        delete callback;
    }

    public:
    Timer():
        m_body(nullptr)
    {}

    Timer(Timer&& other):
        m_body(nullptr)
    {
        (*this) = std::move(other);
    }

    Timer& operator=(Timer&& other)
    {
        if (&other != this) {
            stop();
            m_body = other.m_body;
            m_body->timer = this;
            other.m_body = nullptr;
        }
        return *this;
    }

    ~Timer()
    {
        stop();
    }

    void stop()
    {
        if (m_body) {
            assert(m_body->timer == this);
            assert(m_body->callback);
            delete m_body->callback;
            if (m_body->token) {
                m_body->token->unset();
                delete m_body->token;
            }
            delete m_body;
            m_body = nullptr;
        }
    }

    bool active() const
    {
        return m_body != nullptr;
    }


    /*
     * Used for constructing a timer object from component. Library only.
     */
    void set(Callback* callback)
    {
        if (m_body) {
            stop();
        }
        m_body = new Body;
        m_body->callback = callback;
        m_body->token = nullptr;
        m_body->timer = this;
    }

    void set_token(Token* token)
    {
        assert(m_body);
        m_body->token = token;
    }

    Body* body()
    {
        return m_body;
    }
};

}

#endif
