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
#include <json/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct EchochamberConnection
{
    Jabberite* settings;
    int fd;

    size_t message_size_buffer_size;
    unsigned char message_size_buffer[4];
    uint32_t message_size;
    std::string message_buffer;
};

void echochamber_send(EchochamberConnection *connection, Json::Value value)
{
    Json::StyledWriter writer;
    std::string json_string = writer.write(value);
    uint32_t size = json_string.size();
    unsigned char size_buffer[4];
    for (size_t i = 0; i < sizeof(size_buffer); i++) {
        size_buffer[i] = (size >> (CHAR_BIT * (sizeof(size_buffer) - i - 1))) & 0xff;
    }

    size_t index = 0;
    while (index < sizeof(size_buffer)) {
        int written = write(connection->fd, size_buffer + index, sizeof(size_buffer) - index);
        if (written == -1) {
            fprintf(stderr, "Unable to write to socket\n");
            exit(1);
        }
        index += written;
    }
    index = 0;
    while (index < size) {
        int written = write(connection->fd, json_string.c_str() + index, size - index);
        if (written == -1) {
            fprintf(stderr, "Unable to write to socket\n");
            exit(1);
        }
        index += written;
    }
}

void ui_connection_error(int error_code, std::string description)
{
    fprintf(stderr, "Failed to connect to server. Error %d: %s", error_code, description.c_str());
    abort();
}

void ui_signed_on(std::string username, void* data)
{
    UNUSED(username);
    UNUSED(data);
}

void ui_try_np1sec_join(std::string room, std::string username, std::vector<std::string> users, void* data)
{
    UNUSED(room);
    UNUSED(username);
    UNUSED(users);
    UNUSED(data);
}

void ui_join_failed(void* data)
{
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(data);

    Json::Value root(Json::objectValue);
    root["request"] = "disconnected";
    echochamber_send(connection, root);
}

void ui_user_joined(std::string username, void* data)
{
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(data);

    Json::Value root(Json::objectValue);
    root["request"] = "userJoined";
    root["id"] = username;
    echochamber_send(connection, root);
}

void ui_user_left(std::string username, void* data)
{
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(data);

    Json::Value root(Json::objectValue);
    root["request"] = "userLeft";
    root["id"] = username;
    echochamber_send(connection, root);
}

void ui_np1sec_join_succeeded(std::string room, std::string username, std::vector<std::string> users, void* data)
{
    UNUSED(room);
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(data);

    Json::Value participants(Json::arrayValue);
    for (size_t i = 0; i < users.size(); i++) {
        participants.append(users[i]);
    }
    Json::Value root(Json::objectValue);
    root["request"] = "joined";
    root["id"] = username;
    root["participants"] = participants;
    echochamber_send(connection, root);
}

void ui_new_session(std::string room, std::vector<std::string> users, void* data)
{
    UNUSED(room);
    UNUSED(users);
    UNUSED(data);
}

void ui_incoming_message(std::string room, std::string sender, std::string message, void* data)
{
    UNUSED(room);
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(data);

    time_t current_time = time(NULL);
    struct tm* formatted_time = localtime(&current_time);
    char buffer[1024];
    strftime(buffer, sizeof(buffer), "%a %b %d %H:%M:%S %Z %Y", formatted_time);

    Json::Value root(Json::objectValue);
    root["request"] = "received";
    root["from"] = sender;
    root["message"] = message;
    root["date"] = std::string(buffer);;
    echochamber_send(connection, root);
}



static void echochamber_send_message(EchochamberConnection* connection, std::string destination, std::string message)
{
    connection->settings->user_state->send_handler(destination, message);
}

static void echochamber_handle_message(EchochamberConnection* connection)
{
    Json::Value root;
    Json::Reader reader;

    if (!reader.parse(connection->message_buffer.c_str(), root)) {
        fprintf(stderr, "WARNING: unparsable JSON message received: '%s'\n", connection->message_buffer.c_str());
        return;
    }

    std::string request = root.get("request", "nop").asString();
    if (request == "prompt") {
        std::string destination = root.get("to", "").asString();
        std::string message = root.get("message", "").asString();
        if (destination == "") {
            fprintf(stderr, "WARNING: trying to send a message to an empty destination discarded.\n");
            return;
        }
        echochamber_send_message(connection, destination, message);
    } else {
        fprintf(stderr, "WARNING: unrecognized EC request: '%s'\n", request.c_str());
        return;
    }
}

static gboolean echochamber_callback(GIOChannel* io, GIOCondition condition, gpointer p)
{
    UNUSED(condition);
    EchochamberConnection* connection = reinterpret_cast<EchochamberConnection*>(p);

    gchar in;
    GError* error = NULL;

    switch (g_io_channel_read_chars(io, &in, 1, NULL, &error)) {
    case G_IO_STATUS_NORMAL:
        if (connection->message_size_buffer_size < sizeof(connection->message_size_buffer)) {
            connection->message_size_buffer[connection->message_size_buffer_size++] = in;
            if (connection->message_size_buffer_size == sizeof(connection->message_size_buffer)) {
                // big endian
                connection->message_size = 0;
                for (size_t i = 0; i < sizeof(connection->message_size_buffer); i++) {
                    connection->message_size += connection->message_size_buffer[i] << (CHAR_BIT * (sizeof(connection->message_size_buffer) - i - 1));
                }
                connection->message_buffer.clear();
            }
        } else {
            assert(connection->message_buffer.size() < connection->message_size);
            connection->message_buffer.push_back(in);
            if (connection->message_buffer.size() == connection->message_size) {
                echochamber_handle_message(connection);
                connection->message_size_buffer_size = 0;
            }
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
    EchochamberConnection *connection = new EchochamberConnection;
    connection->settings = settings;
    connection->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connection->fd == -1) {
        fprintf(stderr, "Could not create socket\n");
        exit(1);
    }
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, settings->ec_socket.c_str());
    if (connect(connection->fd, (struct sockaddr *)&name, sizeof(name))) {
        fprintf(stderr, "Could not connect to socket\n");
        exit(1);
    }
    connection->message_size_buffer_size = 0;

    GIOChannel* io = g_io_channel_unix_new(connection->fd);
    g_io_add_watch(io, G_IO_IN, echochamber_callback, connection);

    jabberite_connect(settings);

    return connection;
}
