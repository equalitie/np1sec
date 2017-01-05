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

#include <boost/asio/steady_timer.hpp>
#include "src/interface.h"

class Timers {
public:
    class Timer : public std::enable_shared_from_this<Timer>
                , public np1sec::TimerToken {
    public:
        friend class Timers;

        Timer(boost::asio::io_service& ios, Timers& container)
            : _timer(ios)
            , _container(container)
        { }

        void start(uint32_t timeout_ms, np1sec::TimerCallback* callback)
        {
            _timer.expires_from_now(std::chrono::milliseconds(timeout_ms));
            _timer.async_wait([this, self = shared_from_this(), callback]
                    (boost::system::error_code) {
                        if (_stopped) return;
                        callback->execute();
                        _container._timers.erase(this);
                    });
        }

        void unset() override {
            if (_stopped) return;
            _stopped = true;
            _timer.cancel();
            _container._timers.erase(this);
        }

        ~Timer()
        {
            if (_stopped) return;
            _stopped = true;
            _timer.cancel();
        }

    public:
        bool _stopped = false;
        boost::asio::steady_timer _timer;
        Timers& _container;
    };

    Timer* create( boost::asio::io_service& ios
                 , uint32_t timeout_ms
                 , np1sec::TimerCallback* callback) {
        auto t = std::make_shared<Timer>(ios, *this);
        _timers.emplace(t.get(), t);
        t->start(timeout_ms, callback);
        return t.get();
    }

private:
    friend class Timer;
    std::map<Timer*, std::shared_ptr<Timer>> _timers;
};
