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
#include "test/chat_mocker.h"

Logger mock_logger(INFO);

static void
check_receive_queue(void *arg)
{
  ((ChatMocker*)arg)->receive();
}

// Default constructor
EventManager::EventManager() : base(nullptr)
{
}

// A simple constructor that copies the event base to simplify adding events
EventManager::EventManager(struct event_base* base)
{
  this->base = base;
}

std::string EventManager::next_identifier()
{
  int elements = size();
  std::stringstream stream;
  stream << std::setfill('0') << std::setw(sizeof(int) * 2) << std::hex << elements;
  return stream.str();
}

std::string* EventManager::add_timeout(event_callback_fn cb, void* arg, timeval* timeout)
{
  std::string* new_ident = new std::string;
  *new_ident = next_identifier();
  timers[*new_ident] = evtimer_new(base, cb, arg);
  evtimer_add(timers[*new_ident], timeout);
  return new_ident;
}

struct event* EventManager::get(std::string* identifier)
{
  auto requested_event =  timers.find(*identifier);
  return (requested_event == timers.end()) ? nullptr : requested_event->second;
}

int EventManager::size()
{
  return timers.size();
}

void EventManager::remove_timeout(std::string* identifier)
{
  event* evt = get(identifier);
  if (evt) {
    event_del(evt);
    timers.erase(*identifier);
  } else {
    mock_logger.warn("trying to delete none-existing timer", __FUNCTION__);
  }
}

