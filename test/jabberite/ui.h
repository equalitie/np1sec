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
}

#include <string>
#include <vector>

#include "src/userstate.h"

void ui_connection_error(int error_code, std::string  description);
void ui_signed_on(std::string username);
void ui_try_np1sec_join(std::string room, std::string username, std::vector<std::string> users);
void ui_np1sec_joined(bool success);
void ui_join_failed();
void ui_user_joined(std::string username);
void ui_user_left(std::string username);

void ui_new_session(std::string room, std::vector<std::string> users);
void ui_incoming_message(std::string room, std::string sender, std::string message);

void ui_main(std::string username, std::string server, std::string room, std::string ec_socket, np1sec::UserState* user_state);

#endif
