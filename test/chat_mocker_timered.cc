/**
 * Multiparty Off-the-Record Messaging library
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
   This is a mock/simulator of a multi party chat protocol runing on the
   same machine for the purpose of testing np1sec
 */

#include "src/userstate.h"
#include "src/common.h"
#include "test/chat_mocker_timered.h"

void intermediate_cb(evutil_socket_t fd, short what, void* arg)
{
    (void)fd;
    (void)what;

    auto fn_and_data = reinterpret_cast<pair<timeout_callback, void*>*>(arg);
    fn_and_data->first(fn_and_data->second);
}

void check_receive_queue(evutil_socket_t fd, short what, void* arg)
{
    (void)fd;
    (void)what;
    ((ChatMockerTimered*)arg)->receive();

    ((ChatMockerTimered*)arg)
        ->event_manager.add_timeout(check_receive_queue, arg, &(((ChatMockerTimered*)arg)->c_check_receive_interval));
}

// Default constructor
EventManager::EventManager() : base(nullptr) { base = event_base_new(); }

// A simple constructor that copies the event base to simplify adding events
EventManager::EventManager(struct event_base* base) { this->base = base; }

std::string EventManager::next_identifier()
{
    uid++;
    std::stringstream stream;
    stream << std::setfill('0') << std::setw(sizeof(int) * 2) << std::hex << uid;
    return stream.str();
}

std::string* EventManager::add_timeout(event_callback_fn cb, void* arg, const timeval* timeout)
{
    std::string* new_ident = new std::string;
    *new_ident = next_identifier();
    timers[*new_ident] = evtimer_new(base, cb, arg);
    evtimer_add(timers[*new_ident], timeout);
    return new_ident;
}

struct event* EventManager::get(std::string* identifier)
{
    auto requested_event = timers.find(*identifier);
    return (requested_event == timers.end()) ? nullptr : requested_event->second;
}

int EventManager::size() { return timers.size(); }

void EventManager::remove_timeout(std::string* identifier)
{
    event* evt = get(identifier);
    if (evt) {
        // Delete an event and check that the return code is 0 (success)
        bool event_deleted = evtimer_del(evt) == 0;
        // bool event_deleted = event_del(evt) == 0;
        if (event_deleted) {
            mock_logger.debug("Event with id " + *identifier + " deleted successfully.");
        } else {
            mock_logger.warn("Event with id " + *identifier + " not deleted!");
        }
        timers.erase(*identifier);
    } else {
        mock_logger.warn("trying to delete none-existing timer", __FUNCTION__);
        mock_logger.warn(*identifier);
    }
}

void EventManager::end_event_loop() { event_base_loopexit(base, 0); }

void EventManager::dispatch_event_loop() { event_base_dispatch(base); }

void ChatMockerTimered::dispatch_event_loop()
{
    event_manager.add_timeout(check_receive_queue, (void*)this, &c_check_receive_interval);
    event_manager.dispatch_event_loop();
}
