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
  return timers[*identifier];
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
  }
}

// #define CUSTOM_USER_DIRECTORY "/tmp/test_user"
// #define CUSTOM_PLUGIN_PATH ""
// #define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
// #define UI_ID "test_client"

// char server[128];
// char room[128];

// void write_conv(PurpleConversation *conv,
//                 const char *who, const char *alias,
//                 const char *message,
//                 PurpleMessageFlags flags,
//                 time_t mtime) {
//   UNUSED(conv);
//   UNUSED(flags);
//   UNUSED(mtime);
//   const char *name = NULL;
//   if (alias && *alias)
//     name = alias;
//   else if (who && *who)
//     name = who;
//   printf("%s> %s\n", name, message);
// }

// PurpleConversationUiOps conv_uiops = {
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   write_conv,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL
// };

// void ui_init(void) {
//   purple_conversations_set_ui_ops(&conv_uiops);
// }

// static PurpleCoreUiOps uiops = {
//   NULL,
//   NULL,
//   ui_init,
//   NULL,
//   NULL,
//   NULL,
//   NULL,
//   NULL
// };

// static void signed_on(PurpleConnection *gc, gpointer null) {
//   UNUSED(null);
//   PurpleAccount *account = purple_connection_get_account(gc);
//   printf("Account connected: %s %s\n",
//          account->username, account->protocol_id);

//   GHashTable *components = g_hash_table_new(g_str_hash, g_str_equal);
//   g_hash_table_insert(components, strdup("room"), strdup(room));
//   g_hash_table_insert(components, strdup("server"), strdup(server));
//   serv_join_chat(gc, components);
// }

// static void process_sending_chat(PurpleAccount *account,
//                                  char **message, int id,
//                                  void *m) {
//   UNUSED(account);
//   np1secUserState* user_state = reinterpret_cast<np1secUserState*>(m);
//   std::string prefix = std::string("np1sec:");
//   prefix.append(*message);
//   free(*message);
//   *message = strdup(prefix.c_str());
//   // PurpleConnection *gc = purple_account_get_connection(account);
//   // PurpleConversation *conv = purple_find_chat(gc, id);
//   // user_state->send_handler(conv->name, *message);
// }

// static gboolean process_receiving_chat(PurpleAccount *account, char **sender,
//                                        char **message,
//                                        PurpleConversation *conv,
//                                        int *flags, void *m) {
//   UNUSED(account);
//   UNUSED(sender);
//   UNUSED(flags);
//   np1secUserState* user_state = reinterpret_cast<np1secUserState*>(m);
//   std::string prefix = std::string("np1sec:");
//   prefix.append(*message);
//   free(*message);
//   *message = strdup(prefix.c_str());
//   // user_state->receive_handler(conv->name, prefix);
//   return FALSE;
// }

// static void process_chat_join_failed(PurpleConnection *gc,
//                                      GHashTable *components, void *m) {
//   UNUSED(gc);
//   UNUSED(components);
//   UNUSED(m);
//   printf("Join failed :(\n");
// }

// static void process_chat_joined(PurpleConversation *conv, void *m) {
//   np1secUserState* user_state = reinterpret_cast<np1secUserState*>(m);
//   bool joined = user_state->join_room(conv->name);
//   printf("Joining %s: %s\n", conv->name, joined ? "succeeded" : "failed");
// }

// static void process_buddy_chat_joined(PurpleConversation *conv,
//                                       const char *name,
//                                       PurpleConvChatBuddyFlags flags,
//                                       gboolean new_arrival, void *m) {
//   UNUSED(conv);
//   UNUSED(flags);
//   UNUSED(new_arrival);
//   UNUSED(m);
//   printf("%s joined the chat\n", name);
// }

// static void process_chat_buddy_left(PurpleConversation *conv,
//                             const char *name,
//                             const char *reason, void *m) {
//   UNUSED(conv);
//   UNUSED(reason);
//   UNUSED(m);
//   printf("%s left the chat\n", name);
// }

// static void connect_to_signals(np1secUserState* user_state) {
//   static int handle;
//   void *conn_handle = purple_connections_get_handle();
//   void *conv_handle = purple_conversations_get_handle();

//   purple_signal_connect(conn_handle, "signed-on", &handle,
//            PURPLE_CALLBACK(signed_on), user_state);
//   purple_signal_connect(conv_handle, "sending-chat-msg", &handle,
//            PURPLE_CALLBACK(process_sending_chat), user_state);
//   purple_signal_connect(conv_handle, "receiving-chat-msg", &handle,
//            PURPLE_CALLBACK(process_receiving_chat), user_state);
//   purple_signal_connect(conv_handle, "chat-join-failed", &handle,
//            PURPLE_CALLBACK(process_chat_join_failed), user_state);
//   purple_signal_connect(conv_handle, "chat-joined", &handle,
//            PURPLE_CALLBACK(process_chat_joined), user_state);
//   purple_signal_connect(conv_handle, "chat-buddy-joined", &handle,
//            PURPLE_CALLBACK(process_buddy_chat_joined), user_state);
//   purple_signal_connect(conv_handle, "chat-buddy-left", &handle,
//            PURPLE_CALLBACK(process_chat_buddy_left), user_state);
// }

// #define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
// #define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

// typedef struct _PurpleGLibIOClosure {
//   PurpleInputFunction function;
//   guint result;
//   gpointer data;
// } PurpleGLibIOClosure;

// void purple_glib_io_destroy(gpointer data) {
//   g_free(data);
// }

// gboolean purple_glib_io_invoke(GIOChannel *source, GIOCondition condition,
//                                gpointer data) {
//   PurpleGLibIOClosure *closure = static_cast<PurpleGLibIOClosure *>(data);
//   int purple_cond = 0;

//   if (condition & PURPLE_GLIB_READ_COND)
//     purple_cond |= PURPLE_INPUT_READ;
//   if (condition & PURPLE_GLIB_WRITE_COND)
//     purple_cond |= PURPLE_INPUT_WRITE;

//   closure->function(closure->data, g_io_channel_unix_get_fd(source),
//                     static_cast<PurpleInputCondition>(purple_cond));

//   return TRUE;
// }

// guint glib_input_add(gint fd, PurpleInputCondition condition,
//                      PurpleInputFunction function, gpointer data) {
//   PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
//   GIOChannel *channel;
//   int cond = 0;

//   closure->function = function;
//   closure->data = data;

//   if (condition & PURPLE_INPUT_READ)
//     cond |= PURPLE_GLIB_READ_COND;
//   if (condition & PURPLE_INPUT_WRITE)
//     cond |= PURPLE_GLIB_WRITE_COND;

// #if defined _WIN32 && !defined WINPIDGIN_USE_GLIB_IO_CHANNEL
//   channel = wpurple_g_io_channel_win32_new_socket(fd);
// #else
//   channel = g_io_channel_unix_new(fd);
// #endif
//   closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
//                                         static_cast<GIOCondition>(cond),
//                                         purple_glib_io_invoke, closure,
//                                         purple_glib_io_destroy);

//   g_io_channel_unref(channel);
//   return closure->result;
// }

// PurpleEventLoopUiOps glib_eventloops = {
//   g_timeout_add,
//   g_source_remove,
//   glib_input_add,
//   g_source_remove,
//   NULL,
// #if GLIB_CHECK_VERSION(2, 14, 0)
//   g_timeout_add_seconds,
// #else
//   NULL,
// #endif
//   NULL,
//   NULL,
//   NULL
// };

// void purple_init(void) {
//   purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
//   purple_debug_set_enabled(FALSE);
//   purple_core_set_ui_ops(&uiops);
//   purple_eventloop_set_ui_ops(&glib_eventloops);
//   purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);

//   if (!purple_core_init(UI_ID)) {
//     printf("initializing libpurple failed\n");
//     abort();
//   }

//   purple_set_blist(purple_blist_new());
//   purple_blist_load();
//   purple_prefs_load();
//   purple_plugins_load_saved(PLUGIN_SAVE_PREF);
//   purple_pounces_load();
// }

// static gboolean io_callback(GIOChannel *io, GIOCondition condition,
//                             gpointer p) {
//   UNUSED(condition);
//   PurpleAccount *account = reinterpret_cast<PurpleAccount *>(p);
//   gchar in;
//   GError *error = NULL;
//   static char buf[128];
//   static int ind = 0;

//   char *name = g_strdup_printf("%s@%s", room, server);
//   PurpleConversation *conv = purple_find_conversation_with_account(
//     PURPLE_CONV_TYPE_CHAT, name, account);
//   g_free(name);

//   switch (g_io_channel_read_chars(io, &in, 1, NULL, &error)) {
//   case G_IO_STATUS_NORMAL:
//     buf[ind++] = in;
//     if (ind == 128 || in == '\n') {
//       buf[ind-1] = '\0';
//       purple_conv_chat_send(PURPLE_CONV_CHAT(conv), strdup(buf));
//       ind = 0;
//     }
//     return TRUE;
//   case G_IO_STATUS_ERROR:
//     g_printerr("IO error: %s\n", error->message);
//     g_error_free(error);
//     return FALSE;
//   case G_IO_STATUS_EOF:
//   case G_IO_STATUS_AGAIN:
//     return TRUE;
//     break;
//   }

//   return FALSE;
// }

// void log(std::string room_name, std::string message) {
//   fprintf(stderr, "room: %s / message: %s\n", room_name.c_str(),
//           message.c_str());
// }

// int main(void) {
//   GMainLoop *loop = g_main_loop_new(NULL, FALSE);
//   purple_init();
//   std::string xmpp = "XMPP";
//   GList *iter = purple_plugins_get_protocols();
//   const char *prpl = NULL;
//   for (; iter; iter = iter->next) {
//     PurplePlugin *plugin = static_cast<PurplePlugin *>(iter->data);
//     PurplePluginInfo *info = plugin->info;
//     if (info && info->name && !strcmp(xmpp.c_str(), info->name)) {
//       prpl = info->id;
//       break;
//     }
//   }
//   if (!prpl) {
//     fprintf(stderr, "Failed to gets protocol.");
//     abort();
//   }

//   printf("XMPP account: ");
//   char name[128];
//   char *res = fgets(name, sizeof(name), stdin);
//   if (!res) {
//     fprintf(stderr, "Failed to read user name.");
//     abort();
//   }
//   name[strlen(name) - 1] = 0;  // strip the \n

//   // here is the place to construct the user state
//   static np1secAppOps ops = {
//     log
//   };

//   np1secUserState* user_state = new np1secUserState(name, &ops);
//   if (!user_state->init()) {
//     fprintf(stderr, "Failed to initiate the userstate.\n");
//     abort();
//   }

//   PurpleAccount *account = purple_account_new(name, prpl);
//   char *password = getpass("Password: ");
//   purple_account_set_password(account, password);
//   purple_account_set_enabled(account, UI_ID, TRUE);

//   PurpleSavedStatus *status = purple_savedstatus_new(NULL,
//                               PURPLE_STATUS_AVAILABLE);
//   purple_savedstatus_activate(status);

//   // user_state need to be sent in order to be available to call backs
//   connect_to_signals(user_state);

//   printf("Conference server: ");
//   res = fgets(server, sizeof(server), stdin);
//   if (!res) {
//     fprintf(stderr, "Failed to read conference server.");
//     abort();
//   }
//   server[strlen(server) - 1] = 0;  // strip the \n

//   printf("Room name: ");
//   res = fgets(room, sizeof(room), stdin);
//   if (!res) {
//     fprintf(stderr, "Failed to read room's name.");
//     abort();
//   }
//   room[strlen(room) - 1] = 0;  // strip the \n

//   GIOChannel *io = g_io_channel_unix_new(STDIN_FILENO);
//   g_io_add_watch(io, G_IO_IN, io_callback, account);
//   g_main_loop_run(loop);

//   return 0;
// }
/**
 * join the room by adding the name of the participant to the room list
 */
/*void ChatMocker::join(std::string room, std::string nick) {
  rooms[room].join(nick);
  }*/

