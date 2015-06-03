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

#include <utility>
#include "contrib/gtest/include/gtest/gtesh.h"
#include "src/session.h"
#include "test/chat_mocker.h"
#include "event2/event.h"

const uint32_t five_seconds_mic = 5000000; // Microseconds

class TimerTest : public ::testing::Test
{
protected:
  ChatMocker mock_server;
  struct event_base* base;

  virtual void SetUp()
  {
    base = event_base_new();
    mock_server.initialize_event_manager(base);
  }
};

// TODO
// Either extend test_fire_timer and test_stop_timer to include some assertions to verify the
// correctness of each callback or else augment the calls to each callback so that each call has
// appropriate assertions made.
void test_fire_timer(ChatMocker chat_server, struct event_base* base, void (*timer)(void* arg), void* arg)
{
  pair<ChatMocker*, std::string>* encoded(&chat_server, "");
  set_timer(timer, arg, five_seconds_mic, encoded);
  event_base_dispatch(base);
}

void test_stop_timer(ChatMocker chat_server, struct event_base* base, void (*timer)(void* arg), void* arg)
{
  pair<ChatMocker*, std::string>* encoded(&chat_server, "");
  std::string identifier = set_timer(timer, arg, five_seconds_mic, encoded);
  event_base_dispatch(base);
  axe_timer(identifier, encoded);
}

TEST_F(TimerTest, test_timers)
{
  test_fire_timer(
}
