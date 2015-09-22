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

#include <gtest/gtest.h>
#include "src/userstate.h"

AppOps ops;

class UserStateTest : public ::testing::Test
{
};

TEST_F(UserStateTest, test_init)
{
    std::string name = "tester";
    UserState* user_state = new UserState(name, &ops);
    EXPECT_TRUE(user_state->init());
}

TEST_F(UserStateTest, test_join)
{
    std::string name = "tester";
    std::string room_name = "room";
    UserState* user_state = new UserState(name, &ops);
    ASSERT_TRUE(user_state->init());
    ASSERT_TRUE(user_state->join_room(room_name));
}

TEST_F(UserStateTest, test_join_accept)
{
    std::string accepter_name = "accepter";
    std::string joiner_name = "joiner";
    std::string room_name = "room";
    UserState* joiner_state = new UserState(joiner_name, &ops);
    UserState* accepter_state = new UserState(accepter_name, &ops);
    ASSERT_TRUE(accepter_state->init());
    ASSERT_TRUE(joiner_state->init());
    ASSERT_TRUE(accepter_state->join_room(room_name));
    ASSERT_TRUE(joiner_state->join_room(room_name));
}
