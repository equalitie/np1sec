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

extern "C" {
#include <glib.h>
#include <signal.h>
#include <unistd.h>
}

#include <getopt.h>
#include <cstdint>
#include <string>
#include <map>

extern "C" {
#include "purple.h"
  //#include "conversation.h"
}

#include "src/userstate.h"
#include "src/common.h"
#include "test/jabberite_np1sec_plugin.h"
#include "src/interface.h"

#define CUSTOM_USER_DIRECTORY "/tmp/test_user"
#define CUSTOM_PLUGIN_PATH ""
#define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
#define UI_ID "test_client"

char* server = NULL; //it shouldn't be like this, don't use global variables :(
char* room_name = NULL;

std::map<std::string, uint32_t> message_id;

void write_conv(PurpleConversation* conv, const char* who, const char* alias, const char* message,
                PurpleMessageFlags flags, time_t mtime)
{
    UNUSED(conv);
    UNUSED(flags);
    UNUSED(mtime);
    const char* name = NULL;
    if (alias && *alias)
        name = alias;
    else if (who && *who)
        name = who;
    printf("%s> %s\n", name, message);
}

PurpleConversationUiOps conv_uiops = {NULL, NULL, NULL, NULL, write_conv, NULL, NULL, NULL, NULL, NULL,
                                      NULL, NULL, NULL, NULL, NULL,       NULL, NULL, NULL, NULL};

void ui_init(void) { purple_conversations_set_ui_ops(&conv_uiops); }

static PurpleCoreUiOps uiops = {NULL, NULL, ui_init, NULL, NULL, NULL, NULL, NULL};

static void connection_error(PurpleConnection *gc, PurpleConnectionError err, const gchar *desc)
{
  UNUSED(desc);
  UNUSED(gc);
  fprintf(stderr, "Failed to connect to server. Error code %d: see libpurple/connection.h for description", err);
  abort();

}
static void signed_on(PurpleConnection* gc, gpointer null)
{
    UNUSED(null);
    PurpleAccount* account = purple_connection_get_account(gc);
    printf("Account connected: %s %s\n", account->username, account->protocol_id);

    GHashTable* components = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(components, strdup("room"), strdup(room_name));
    g_hash_table_insert(components, strdup("server"), strdup(server));
    serv_join_chat(gc, components);
}

//we should not interfere with send as it is bare send which is sending
//instead we interfere with io_callback and get the data through (n+1)sec
// static void process_sending_chat(PurpleAccount* account, char** message, int id, void* m)
// {
//     UNUSED(account);
//     UNUSED(id);
//     np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(m);
//     //std::string prefix = std::string("np1sec:");
//     //prefix.append(*message);
//     //free(*message);
//     //*message = strdup(prefix.c_str());
//     PurpleConnection *gc = purple_account_get_connection(account);
//     PurpleConversation *conv = purple_find_chat(gc, id);
//     user_state->send_handler(conv->name, *message);
// }

static gboolean process_receiving_chat(PurpleAccount* account, char** sender, char** message, PurpleConversation* conv,
                                       int* flags, void* m)
{
    UNUSED(account);
    UNUSED(sender);
    UNUSED(flags);
    np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(m);
    // std::string prefix = std::string("np1sec:");
    // prefix.append(*message);
    // free(*message);
    // *message = strdup(prefix.c_str());
    message_id[conv->name]++;
    user_state->receive_handler(conv->name, *sender, *message, message_id[conv->name]);
    return FALSE;
}

static void process_chat_join_failed(PurpleConnection* gc, GHashTable* components, void* m)
{
    UNUSED(gc);
    UNUSED(components);
    UNUSED(m);
    printf("Join failed :(\n");
}

// static void process_chat_joined(PurpleConversation* conv, void* m)
// {
//     np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(m);
//     // todo: Arlo could you convert conv->chat to vector<string>

//     //    GList* g_participant_list =	purple_conv_chat_get_users(cur_chat);
//     //    std::cout << (char*)g_participant_list->data << std::endl;
//     (void) user_state;
//     //bool joined = user_state->join_room(conv->name, current_occupants);
//     //message_id[conv->name]=0;
//     //printf("Joining %s: %s\n", conv->name, joined ? "succeeded" : "failed");

// }

static void process_buddy_chat_joined(PurpleConversation* conv, const char* name, PurpleConvChatBuddyFlags flags,
                                      gboolean new_arrival, void* m)
{
    UNUSED(flags);
    UNUSED(new_arrival);
    np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(m);
    printf("%s joined the chat is new %d\n", name, new_arrival);

    //in general we don't care about this handle. new users are responsible
    //to initiate the join to the secure session. We only are using this
    //for the time that we join. To detect that it is the time of our join
    //we check if the user joined is us.
    //this is quite aweful but I have not found a better handle to find out how many
    //people are in the room at the time of joining
    if (user_state->user_nick() == name) {//we are joining
      //we need to check if we are alone.
      GList* g_participant_list =	purple_conv_chat_get_users(PURPLE_CONV_CHAT(conv));
      bool joined = user_state->join_room(conv->name, g_list_length(g_participant_list));
      
      printf("Initating Join to room %s: %s\n", conv->name, joined ? "succeeded" : "failed");
      
    }
   // for (; g_participant_list != NULL; g_participant_list = g_participant_list->next)
   //   {
   //     PurpleConvChatBuddy* cbuddy = (PurpleConvChatBuddy *)(g_participant_list->data);
   //     //std::cout << cbuddy->name << std::endl;
   //     if (cbuddy->name == name)
   //   }
   
}

static void process_chat_buddy_left(PurpleConversation* conv, const char* name, const char* reason, void* m)
{
    UNUSED(conv);
    UNUSED(reason);
    UNUSED(m);
    printf("%s left the chat\n", name);
}

// void chat_conversation_updated(PurpleConversation *conv,
//                                PurpleConvUpdateType type, gpointer data)
// {
//   (void) type;
//   (void) data;
//   PurpleConvChat* cur_chat = purple_conversation_get_chat_data(conv);
//   purple_conv_chat_send (cur_chat, "conv_update");

// }

void send_bare(std::string room_name, std::string message, void* data)
{
  PurpleAccount* account = reinterpret_cast<PurpleAccount*>(data);
  //char* name = g_strdup_printf("%s@%s", room_name.c_str(), server);
  PurpleConversation* conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, room_name.c_str(), account);

  purple_conv_chat_send(PURPLE_CONV_CHAT(conv), message.c_str());

}

static void connect_to_signals(np1sec::UserState* user_state)
{
    static int handle;
    void* conn_handle = purple_connections_get_handle();
    void* conv_handle = purple_conversations_get_handle();

    purple_signal_connect(conn_handle, "connection-error", &handle, PURPLE_CALLBACK(connection_error), user_state);
	                       
    purple_signal_connect(conn_handle, "signed-on", &handle, PURPLE_CALLBACK(signed_on), user_state);
    //purple_signal_connect(conv_handle, "sending-chat-msg", &handle, PURPLE_CALLBACK(process_sending_chat), user_state);
    purple_signal_connect(conv_handle, "receiving-chat-msg", &handle, PURPLE_CALLBACK(process_receiving_chat),
                          user_state);
    purple_signal_connect(conv_handle, "chat-join-failed", &handle, PURPLE_CALLBACK(process_chat_join_failed),
                          user_state);
    //purple_signal_connect(conv_handle, "chat-joined", &handle, PURPLE_CALLBACK(process_chat_joined), user_state);
    //purple_signal_connect(conv_handle, "conversation-updated", &handle, PURPLE_CALLBACK(chat_conversation_updated), user_state);
    purple_signal_connect(conv_handle, "chat-buddy-joined", &handle, PURPLE_CALLBACK(process_buddy_chat_joined),
                          user_state);
    purple_signal_connect(conv_handle, "chat-buddy-left", &handle, PURPLE_CALLBACK(process_chat_buddy_left),
                          user_state);
}

#define PURPLE_GLIB_READ_COND (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
    PurpleInputFunction function;
    guint result;
    gpointer data;
} PurpleGLibIOClosure;


void purple_glib_io_destroy(gpointer data) { g_free(data); }

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

PurpleEventLoopUiOps glib_eventloops = {g_timeout_add,
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
                                        NULL};

void purple_init(void)
{
    purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
    purple_debug_set_enabled(FALSE);
    purple_core_set_ui_ops(&uiops);
    purple_eventloop_set_ui_ops(&glib_eventloops);
    purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);

    if (!purple_core_init(UI_ID)) {
        printf("initializing libpurple failed\n");
        abort();
    }

    purple_set_blist(purple_blist_new());
    purple_blist_load();
    purple_prefs_load();
    purple_plugins_load_saved(PLUGIN_SAVE_PREF);
    purple_pounces_load();
}

static gboolean io_callback(GIOChannel* io, GIOCondition condition, gpointer p)
{
    UNUSED(condition);
    //we don't need the account we have sent it as send_bare_data before
    // PurpleAccount* account = (static_cast<pair<PurpleAccount*, np1sec::UserState*>*>(p))->first;
    // np1sec::UserState* user_state = (static_cast<pair<PurpleAccount*, np1sec::UserState*>*>(p))->second;
    np1sec::UserState* user_state = reinterpret_cast<np1sec::UserState*>(p);
    
    gchar in;
    GError* error = NULL;
    static char buf[128];
    static int ind = 0;

    //PurpleConversation* conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, name, account);

    switch (g_io_channel_read_chars(io, &in, 1, NULL, &error)) {
    case G_IO_STATUS_NORMAL:
        buf[ind++] = in;
        if (ind == 128 || in == '\n') {
          char* name = g_strdup_printf("%s@%s", room_name, server);
          user_state->send_handler(name, strdup(buf));
          g_free(name);
          //purple_conv_chat_send(PURPLE_CONV_CHAT(conv), strdup(buf));
            ind = 0;
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

void log(std::string room_name, std::string message)
{
    fprintf(stderr, "room: %s / message: %s\n", room_name.c_str(), message.c_str());
}

const char* program_name;

/* Prints usage information for this program to STREAM (typically
stdout or stderr), and exit the program with EXIT_CODE. Does not
return. */
void print_usage (FILE* stream, int exit_code)
{
  fprintf (stream, "Usage: %s options [ inputfile ... ]\n", program_name);
  fprintf (stream, " -h --help          Display this usage information.\n"
           " -a --account  xmpp account The xmpp account used for login\n"
           " -p --password password     The password for the login\n"
           " -s --server   server name  The conference server\n"
           " -r --room     room name    The room name to join\n");
  exit (exit_code);
}

int main(int argc, char* argv[])
{
    GMainLoop* loop = g_main_loop_new(NULL, FALSE);
    purple_init();
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
        fprintf(stderr, "Failed to gets protocol.");
        abort();
    }

    //Dealing with command line option
    /* A string listing valid short options letters.*/
    const char* const short_options = "ha:p:s:r:";
    /* An array describing valid long options. */
    const struct option long_options[] = {
      { "help", 0, NULL, 'h' },
      { "account", 1, NULL, 'a' },
      { "password", 1, NULL, 'p' },
      { "server", 1, NULL, 's' },
      { "room", 1, NULL, 'r' },
      { NULL, 0, NULL, 0 }
    };


    program_name = argv[0];
    int next_option;
    //user inputs
    char* user_name = NULL;
    char* password = NULL;
    do {
      next_option = getopt_long (argc, argv, short_options, long_options, NULL);
      switch (next_option)
        {
        case 'h':
          /* -h or --help */
          /* User has requested usage information. Print it to standard
             output, and exit with exit code zero (normal termination). */
          print_usage (stdout, 0);
        case 'a':
          /* -a or --account */
             user_name = optarg;
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
             room_name = optarg;
             break;
        case '?':
          /* The user specified an invalid option. */
          /* Print usage information to standard error, and exit with exit
             code one (indicating abnormal termination). */
          print_usage (stderr, 1);
        case -1:
          break;
          /* Done with options.
           */
        default:
          /* Something else: unexpected.*/
             abort ();
        }

    }
    while (next_option != -1);
    
    if (user_name == NULL) {
      printf("XMPP account: ");
      user_name = new char[128];
      char* res = fgets(user_name, sizeof(user_name), stdin);
      if (!res) {
        fprintf(stderr, "Failed to read user name.");
        abort();
      }
      user_name[strlen(user_name) - 1] = 0; // strip the \n
    }

    // here is the place to construct the user state
    uint32_t hundred_mili_sec = 100;
    uint32_t one_sec = 1000;

    // AppOps(uint32_t ACK_GRACE_INTERVAL,
    //          uint32_t REKEY_GRACE_INTERVAL,
    //          uint32_t INTERACTION_GRACE_INTERVAL,
    //          uint32_t BROADCAST_LATENCY)
    static np1sec::AppOps ops(hundred_mili_sec, one_sec, hundred_mili_sec, hundred_mili_sec);;

    ops.send_bare = send_bare;
    ops.join = new_session_announce;
    ops.display_message = display_message;
    ops.set_timer = set_timer;
    ops.axe_timer = axe_timer;

    //ops.leave = new_session_announce;

    PurpleAccount* account = purple_account_new(user_name, prpl);
    ops.bare_sender_data = static_cast<void*>(account);
    np1sec::logger.debug("Set bare_sender_data");

    //we drop the server name get the nick
    std::string nick(user_name);
    size_t at_pos = nick.find('@');
    if (at_pos != std::string::npos)
      nick = nick.substr(0, at_pos);
    
    np1sec::UserState user_state(nick, &ops, nullptr);
    if (!user_state.init()) {
        fprintf(stderr, "Failed to initiate the userstate.\n");
        abort();
    }
    np1sec::logger.debug("Initialized user_state");
    
    if (password == NULL) {
      password = getpass("Password: ");
    }
    purple_account_set_password(account, password);

    //set status available to later force libpurple to connect
    purple_account_set_enabled(account, UI_ID, TRUE);
    PurpleSavedStatus* status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
    purple_savedstatus_activate(status);

    //PurpleStatus* cur_status = purple_account_get_active_status(account);

    // user_state need to be sent in order to be available to call backs
    connect_to_signals(&user_state);

    if (server == NULL) {
      server = new char[1024];
      printf("Conference server: ");
      char* res = fgets(server, sizeof(server), stdin);
      if (!res) {
        fprintf(stderr, "Failed to read conference server.");
        abort();
      }
        server[strlen(server) - 1] = 0; // strip the \n
    }

    if (room_name == NULL) {
      room_name = new char[128];
      printf("Room name: ");
      char* res = fgets(room_name, sizeof(room_name), stdin);
      if (!res) {
        fprintf(stderr, "Failed to read room's name.");
        abort();
      }

      room_name[strlen(room_name) - 1] = 0; // strip the \n
    }

    GIOChannel* io = g_io_channel_unix_new(STDIN_FILENO);
    g_io_add_watch(io, G_IO_IN, io_callback, &user_state);
    g_main_loop_run(loop);

    delete[] user_name;
    delete[] server;
    delete[] room_name;
    
    return 0;
}
