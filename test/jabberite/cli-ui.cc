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

#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void ui_connection_error(int error_code, std::string description)
{
    fprintf(stderr, "Failed to connect to server. Error %d: %s", error_code, description.c_str());
    abort();
}

void ui_signed_on(std::string username, void* data)
{
    UNUSED(data);

    printf("Account connected: %s\n", username.c_str());
}

void ui_try_np1sec_join(std::string room, std::string username, std::vector<std::string> users, void* data)
{
    UNUSED(data);

    printf("Initiating np1sec join of room '%s' as '%s', participants:", room.c_str(), username.c_str());
    for (size_t i = 0; i < users.size(); i++) {
        printf(" %s", users[i].c_str());
    }
    printf("\n");
}

void ui_np1sec_joined(bool success, void* data)
{
    UNUSED(data);

    if (success) {
        printf("Join succeeded\n");
    } else {
        printf("Join failed\n");
    }
}

void ui_join_failed(void* data)
{
    UNUSED(data);

    printf("Unable to join room\n");
}

void ui_user_joined(std::string username, void* data)
{
    UNUSED(data);

    printf("%s joined the chat\n", username.c_str());
}

void ui_user_left(std::string username, void* data)
{
    UNUSED(data);

    printf("%s left the chat\n", username.c_str());
}

void ui_new_session(std::string room, std::vector<std::string> users, void* data)
{
    UNUSED(data);

    printf("Starting new np1sec session in room '%s' with participants:", room.c_str());
    for (size_t i = 0; i < users.size(); i++) {
        printf(" %s", users[i].c_str());
    }
    printf("\n");
}

void ui_incoming_message(std::string room, std::string sender, std::string message, void* data)
{
    UNUSED(data);

    printf("%s@%s: %s\n", sender.c_str(), room.c_str(), message.c_str());
}



struct StdinData
{
    Jabberite* settings;
    std::string line_buffer;
};

static gboolean stdin_callback(GIOChannel* io, GIOCondition condition, gpointer p)
{
    UNUSED(condition);
    StdinData* data = reinterpret_cast<StdinData*>(p);

    gchar in;
    GError* error = NULL;

    switch (g_io_channel_read_chars(io, &in, 1, NULL, &error)) {
    case G_IO_STATUS_NORMAL:
        if (in != '\n') {
            data->line_buffer += in;
        } else {
            data->settings->user_state->send_handler(data->settings->room + "@" + data->settings->server, data->line_buffer);
            data->line_buffer.clear();
        }
        return TRUE;
    case G_IO_STATUS_ERROR:
        g_printerr("IO error: %s\n", error->message);
        g_error_free(error);
        return FALSE;
    case G_IO_STATUS_EOF:
    case G_IO_STATUS_AGAIN:
        return TRUE;
        break;
    }

    return FALSE;
}

void* ui_main(Jabberite* settings)
{
    StdinData *data = new StdinData;
    data->settings = settings;

    GIOChannel* io = g_io_channel_unix_new(STDIN_FILENO);
    g_io_add_watch(io, G_IO_IN, stdin_callback, data);

    jabberite_connect(settings);

    return NULL;
}
