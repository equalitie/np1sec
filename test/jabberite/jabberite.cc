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

#include <unistd.h>
#include <getopt.h>
#include <string>

#include "src/interface.h"
#include "src/logger.h"

#define CUSTOM_USER_DIRECTORY "/tmp/test_user"
#define CUSTOM_PLUGIN_PATH ""
#define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
#define UI_ID "test_client"



struct Np1secTimer
{
    guint timer_id;
    void (*timer_callback)(void* opdata);
    void *opdata;
};

static gboolean np1sec_execute_timer(gpointer np1sec_timer)
{
    Np1secTimer* timer = reinterpret_cast<Np1secTimer*>(np1sec_timer);

    timer->timer_callback(timer->opdata);
    delete timer;
    // Returning 0 stops the timer.
    return 0;
}

void* np1sec_set_timer(void (*timer_callback)(void* opdata), void* opdata, uint32_t interval, void* data)
{
    UNUSED(data);

    Np1secTimer* timer = new Np1secTimer;
    timer->timer_callback = timer_callback;
    timer->opdata = opdata;
    timer->timer_id = g_timeout_add(interval, np1sec_execute_timer, timer);
    return timer;
}

void np1sec_unset_timer(void* identifier, void* data)
{
    UNUSED(data);
    Np1secTimer* timer = reinterpret_cast<Np1secTimer*>(identifier);

    g_source_remove(timer->timer_id);
    delete timer;
}

void np1sec_new_session(std::string room, std::vector<std::string> users, void* data)
{
    Jabberite* settings = reinterpret_cast<Jabberite*>(data);

    if (!settings->joined) {
        settings->joined = true;
        ui_np1sec_join_succeeded(room, settings->username, users, settings->ui_data);
    }

    ui_new_session(room, users, settings->ui_data);
}

void np1sec_incoming_message(std::string room, std::string sender, std::string message, void* data)
{
    Jabberite* settings = reinterpret_cast<Jabberite*>(data);

    ui_incoming_message(room, sender, message, settings->ui_data);
}

void np1sec_send(std::string room, std::string message, void* data)
{
    Jabberite* settings = reinterpret_cast<Jabberite*>(data);

    PurpleConversation* conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, room.c_str(), settings->account);
    purple_conv_chat_send(PURPLE_CONV_CHAT(conv), message.c_str());
}

void setup_np1sec(Jabberite *settings, std::string nick)
{
    // AppOps(uint32_t ACK_GRACE_INTERVAL,
    //        uint32_t REKEY_GRACE_INTERVAL,
    //        uint32_t INTERACTION_GRACE_INTERVAL,
    //        uint32_t BROADCAST_LATENCY)
    static np1sec::AppOps* ops = new np1sec::AppOps(15000, 60000, 2000, 2000);

    ops->bare_sender_data = settings;
    ops->send_bare = np1sec_send;
    ops->join = np1sec_new_session;
    ops->leave = np1sec_new_session;
    ops->display_message = np1sec_incoming_message;
    ops->set_timer = np1sec_set_timer;
    ops->axe_timer = np1sec_unset_timer;

    settings->user_state = new np1sec::UserState(nick, ops);
    np1sec::logger.debug("Initialized user_state");
}





static void process_connection_error(PurpleConnection *gc, PurpleConnectionError err, const gchar *desc)
{
    UNUSED(gc);

    ui_connection_error(err, desc);
}

static void process_signed_on(PurpleConnection* conn, void *m)
{
    Jabberite* settings = reinterpret_cast<Jabberite*>(m);

    PurpleAccount* account = purple_connection_get_account(conn);
    ui_signed_on(account->username, settings->ui_data);

    GHashTable* components = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(components, strdup("room"), strdup(settings->room.c_str()));
    g_hash_table_insert(components, strdup("server"), strdup(settings->server.c_str()));
    serv_join_chat(conn, components);
}

static void process_chat_join_failed(PurpleConnection* gc, GHashTable* components, void* m)
{
    UNUSED(gc);
    UNUSED(components);
    Jabberite* settings = reinterpret_cast<Jabberite*>(m);

    ui_join_failed(settings->ui_data);
}

static void process_buddy_chat_joined(PurpleConversation* conv, const char* name, PurpleConvChatBuddyFlags flags, gboolean new_arrival, void* m)
{
    UNUSED(flags);
    UNUSED(new_arrival);
    Jabberite* settings = reinterpret_cast<Jabberite*>(m);

    if (!new_arrival && settings->user_state->user_nick() == name) {
        std::vector<std::string> user_vector;
        GList* user_list = purple_conv_chat_get_users(PURPLE_CONV_CHAT(conv));
        while (user_list) {
            PurpleConvChatBuddy* buddy = reinterpret_cast<PurpleConvChatBuddy*>(user_list->data);
            user_vector.push_back(purple_conv_chat_cb_get_name(buddy));
            user_list = user_list->next;
        }

        ui_try_np1sec_join(conv->name, name, user_vector, settings->ui_data);
        settings->user_state->join_room(conv->name, user_vector.size());
    } else if (new_arrival) {
        ui_user_joined(name, settings->ui_data);
    }
}

static void process_chat_buddy_left(PurpleConversation* conv, const char* name, const char* reason, void* m)
{
    UNUSED(conv);
    UNUSED(reason);
    Jabberite* settings = reinterpret_cast<Jabberite*>(m);

    ui_user_left(name, settings->ui_data);
}

static void process_received_chat(PurpleAccount* account, char* sender, char* message, PurpleConversation* conv, int flags, void* m)
{
    UNUSED(account);
    UNUSED(sender);
    UNUSED(flags);
    Jabberite* settings = reinterpret_cast<Jabberite*>(m);

    settings->user_state->receive_handler(conv->name, sender, message);
}

static void setup_purple_callbacks(Jabberite* settings)
{
    static int handle;
    void* conn_handle = purple_connections_get_handle();
    void* conv_handle = purple_conversations_get_handle();

    purple_signal_connect(conn_handle, "connection-error", &handle, PURPLE_CALLBACK(process_connection_error), settings);
    purple_signal_connect(conn_handle, "signed-on", &handle, PURPLE_CALLBACK(process_signed_on), settings);
    purple_signal_connect(conv_handle, "chat-join-failed", &handle, PURPLE_CALLBACK(process_chat_join_failed), settings);
    purple_signal_connect(conv_handle, "chat-buddy-joined", &handle, PURPLE_CALLBACK(process_buddy_chat_joined), settings);
    purple_signal_connect(conv_handle, "chat-buddy-left", &handle, PURPLE_CALLBACK(process_chat_buddy_left), settings);
    purple_signal_connect(conv_handle, "received-chat-msg", &handle, PURPLE_CALLBACK(process_received_chat), settings);
}



/*
 * This structure plugs libpurple into the glib event loop.
 */
/*
 * START copied from libpurple example
 */

#define PURPLE_GLIB_READ_COND (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
    PurpleInputFunction function;
    guint result;
    gpointer data;
} PurpleGLibIOClosure;

void purple_glib_io_destroy(gpointer data)
{
    g_free(data);
}

gboolean purple_glib_io_invoke(GIOChannel* source, GIOCondition condition, gpointer data)
{
    PurpleGLibIOClosure* closure = static_cast<PurpleGLibIOClosure*>(data);
    int purple_cond = 0;

    if (condition & PURPLE_GLIB_READ_COND)
        purple_cond |= PURPLE_INPUT_READ;
    if (condition & PURPLE_GLIB_WRITE_COND)
        purple_cond |= PURPLE_INPUT_WRITE;

    closure->function(closure->data, g_io_channel_unix_get_fd(source), static_cast<PurpleInputCondition>(purple_cond));

    return TRUE;
}

guint glib_input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data)
{
    PurpleGLibIOClosure* closure = g_new0(PurpleGLibIOClosure, 1);
    GIOChannel* channel;
    int cond = 0;

    closure->function = function;
    closure->data = data;

    if (condition & PURPLE_INPUT_READ)
        cond |= PURPLE_GLIB_READ_COND;
    if (condition & PURPLE_INPUT_WRITE)
        cond |= PURPLE_GLIB_WRITE_COND;

#if defined _WIN32 && !defined WINPIDGIN_USE_GLIB_IO_CHANNEL
    channel = wpurple_g_io_channel_win32_new_socket(fd);
#else
    channel = g_io_channel_unix_new(fd);
#endif
    closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, static_cast<GIOCondition>(cond),
                                          purple_glib_io_invoke, closure, purple_glib_io_destroy);

    g_io_channel_unref(channel);
    return closure->result;
}

PurpleEventLoopUiOps glib_eventloops = 
{
    g_timeout_add,
    g_source_remove,
    glib_input_add,
    g_source_remove,
    NULL,
#if GLIB_CHECK_VERSION(2, 14, 0)
    g_timeout_add_seconds,
#else
    NULL,
#endif
    NULL,
    NULL,
    NULL
};

/*
 * END copied from libpurple example
 */

void setup_purple(void)
{
    purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
    purple_debug_set_enabled(FALSE);
    purple_eventloop_set_ui_ops(&glib_eventloops);
    purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);

    if (!purple_core_init(UI_ID)) {
        fprintf(stderr, "initializing libpurple failed\n");
        abort();
    }

    purple_set_blist(purple_blist_new());
    purple_blist_load();
    purple_prefs_load();
    purple_plugins_load_saved(PLUGIN_SAVE_PREF);
    purple_pounces_load();
}



void jabberite_connect(Jabberite *settings)
{
    purple_account_set_enabled(settings->account, UI_ID, TRUE);
    purple_savedstatus_activate(purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE));
}

void do_jabberite(std::string username, std::string password, std::string server, std::string room, int port, std::string ec_socket)
{
    GMainLoop* loop = g_main_loop_new(NULL, FALSE);

    setup_purple();
    std::string xmpp = "XMPP";
    GList* iter = purple_plugins_get_protocols();
    const char* prpl = NULL;
    for (; iter; iter = iter->next) {
        PurplePlugin* plugin = static_cast<PurplePlugin*>(iter->data);
        PurplePluginInfo* info = plugin->info;
        if (info && info->name && !strcmp(xmpp.c_str(), info->name)) {
            prpl = info->id;
            break;
        }
    }
    if (!prpl) {
        fprintf(stderr, "Failed to get protocol.");
        abort();
    }



    std::string nick(username);
    size_t at_pos = nick.find('@');
    if (at_pos != std::string::npos) {
        nick = nick.substr(0, at_pos);
    }



    Jabberite *settings = new Jabberite;
    settings->joined = false;
    settings->username = username;
    settings->password = password;
    settings->server = server;
    settings->room = room;
    settings->port = port;
    settings->ec_socket = ec_socket;

    setup_np1sec(settings, nick);



    settings->account = purple_account_new(username.c_str(), prpl);
    purple_account_set_password(settings->account, password.c_str());
    if (port != -1) {
        purple_account_set_int(settings->account, "port", port);
    }

    setup_purple_callbacks(settings);



    settings->ui_data = ui_main(settings);

    g_main_loop_run(loop);
}

void print_usage(FILE* stream, const char *program_name, int exit_code)
{
    fprintf (stream, "Usage: %s options [ inputfile ... ]\n", program_name);
    fprintf (stream, " -h --help                       Display this usage information.\n"
                     " -a --account    xmpp account    The xmpp account used for login\n"
                     " -p --password   password        The password for the login\n"
                     " -s --server     server name     The conference server\n"
                     " -r --room       room name       The room name to join\n"
                     " -P --port       port number     The port to connect on; defaults to 5222\n"
                     " -e --ec-socket  EC socket name  The socket name through which EchoChamber communicating with jabberite\n"
    );
    exit (exit_code);
}

int main(int argc, char* argv[])
{
    char *username = NULL;
    char *password = NULL;
    char *server = NULL;
    char *room = NULL;
    int port = -1;
    const char *ec_socket = "";


    const char* const short_options = "ha:p:s:P:r:e:";
    const struct option long_options[] = {
        { "help", 0, NULL, 'h' },
        { "account", 1, NULL, 'a' },
        { "password", 1, NULL, 'p' },
        { "server", 1, NULL, 's' },
        { "room", 1, NULL, 'r' },
        { "port", 1, NULL, 'P' },
        { "ec-fd", 1, NULL, 'e' },
        { NULL, 0, NULL, 0 }
    };

    int next_option;
    do {
        next_option = getopt_long (argc, argv, short_options, long_options, NULL);
        switch (next_option)
        {
        case 'h':
            /* -h or --help */
            print_usage(stdout, argv[0], 0);
            break;
        case 'a':
            /* -a or --account */
            username = optarg;
            break;
        case 'p':
            /* -o or --password */
            password = optarg;
            break;
        case 's':
            /* -s or --server */
            server = optarg;
            break;
        case 'r':
            /* -r or --room */
            room = optarg;
            break;
        case 'P':
            /* -P or --port */
            try {
                port = std::stoi(std::string(optarg));
            } catch(std::invalid_argument) {
                print_usage(stdout, argv[0], 1);
            }
            break;
        case 'e':
            /* -e or --ec-sock */
            ec_socket = optarg;
            break;
        case '?':
            /* Invalid option */
            print_usage(stderr, argv[0], 1);
            break;
        case -1:
            /* Done with options */
            break;
        default:
            /* Something else: unexpected.*/
            abort ();
        }
    } while (next_option != -1);

    if (!username) {
        username = new char[128];
        printf("XMPP account: ");
        if (!fgets(username, 128, stdin)) {
            fprintf(stderr, "Failed to read user name.");
            abort();
        }
        if (strrchr(username, '\n')) {
            *strrchr(username, '\n') = 0;
        }
    }

    if (!password) {
        password = getpass("Password: ");
    }

    if (!server) {
        server = new char[1024];
        printf("Conference server: ");
        if (!fgets(server, 1024, stdin)) {
            fprintf(stderr, "Failed to read conference server.");
            abort();
        }
        if (strrchr(server, '\n')) {
            *strrchr(server, '\n') = 0;
        }
    }

    if (!room) {
        room = new char[128];
        printf("Room name: ");
        if (!fgets(room, 128, stdin)) {
            fprintf(stderr, "Failed to read room's name.");
            abort();
        }
        if (strrchr(room, '\n')) {
            *strrchr(room, '\n') = 0;
        }
    }

    do_jabberite(username, password, server, room, port, ec_socket);
}
