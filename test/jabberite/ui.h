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

#ifndef TEST_JABBERITE_UI_H
#define TEST_JABBERITE_UI_H

extern "C" {
#include <glib.h>
#include "purple.h"
}

#include <string>
#include <vector>

#include "src/userstate.h"

#define UNUSED(x) ((void)(x))

struct Jabberite
{
    PurpleAccount* account;
    np1sec::UserState* user_state;

    bool joined;

    std::string username;
    std::string password;
    std::string server;
    std::string room;
    int port;
    std::string ec_socket;

    void* ui_data;
};


void ui_connection_error(int error_code, std::string  description);
void ui_signed_on(std::string username, void* data);
void ui_try_np1sec_join(std::string room, std::string username, std::vector<std::string> users, void* data);
void ui_join_failed(void* data);
void ui_user_joined(std::string username, void* data);
void ui_user_left(std::string username, void* data);
void ui_np1sec_join_succeeded(std::string room, std::string username, std::vector<std::string> users, void* data);

void ui_new_session(std::string room, std::vector<std::string> users, void* data);
void ui_incoming_message(std::string room, std::string sender, std::string message, void* data);

void jabberite_connect(Jabberite *settings);
void* ui_main(Jabberite *settings);

#endif
