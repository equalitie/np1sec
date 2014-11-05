
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

#include <string>

extern "C" {
  #include "purple.h"
}

#include "userstate.h"

#define UNUSED(expr) (void)(expr)
#define CUSTOM_USER_DIRECTORY "/tmp/test_user"
#define CUSTOM_PLUGIN_PATH ""
#define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
#define UI_ID "test_client"

void write_conv(PurpleConversation *conv, const char *who, const char *alias,
                const char *message, PurpleMessageFlags flags, time_t mtime) {
  UNUSED(conv);
  UNUSED(flags);
  UNUSED(mtime);
  const char *name = NULL;
  if (alias && *alias)
    name = alias;
  else if (who && *who)
    name = who;
  printf("%s> %s\n", name, message);
}

PurpleConversationUiOps conv_uiops = {
  NULL,
  NULL,
  NULL,
  NULL,
  write_conv,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

void ui_init(void) {
  purple_conversations_set_ui_ops(&conv_uiops);
}

static PurpleCoreUiOps uiops = {
  NULL,
  NULL,
  ui_init,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static void signed_on(PurpleConnection *gc, gpointer null) {
  UNUSED(null);
  PurpleAccount *account = purple_connection_get_account(gc);
  printf("Account connected: %s %s\n", account->username, account->protocol_id);
}

static void process_sending_im(PurpleAccount *account, char *who,
                               char **message, void *m) {
  UNUSED(account);
  UNUSED(who);
  UNUSED(m);
  std::string prefix = std::string("mpSeQ:");
  prefix.append(*message);
  free(*message);
  *message = strdup(prefix.c_str());
}

static gboolean process_receiving_im(PurpleAccount *account, char **who,
                                     char **message, int *flags, void *m) {
  UNUSED(account);
  UNUSED(who);
  UNUSED(flags);
  UNUSED(m);
  std::string prefix = std::string("mpSeQ:");
  prefix.append(*message);
  free(*message);
  *message = strdup(prefix.c_str());
  return FALSE;
}

static void connect_to_signals(void) {
  static int handle;
  void *conn_handle = purple_connections_get_handle();
  void *conv_handle = purple_conversations_get_handle();

  purple_signal_connect(conn_handle, "signed-on", &handle,
                        PURPLE_CALLBACK(signed_on), NULL);
  purple_signal_connect(conv_handle, "sending-im-msg", &handle,
                        PURPLE_CALLBACK(process_sending_im), NULL);
  purple_signal_connect(conv_handle, "receiving-im-msg", &handle,
                        PURPLE_CALLBACK(process_receiving_im), NULL);
}

#define PURPLE_GLIB_READ_COND  (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
  PurpleInputFunction function;
  guint result;
  gpointer data;
} PurpleGLibIOClosure;

void purple_glib_io_destroy(gpointer data) {
  g_free(data);
}

gboolean purple_glib_io_invoke(GIOChannel *source, GIOCondition condition,
                               gpointer data) {
  PurpleGLibIOClosure *closure = static_cast<PurpleGLibIOClosure *>(data);
  int purple_cond = 0;

  if (condition & PURPLE_GLIB_READ_COND)
    purple_cond |= PURPLE_INPUT_READ;
  if (condition & PURPLE_GLIB_WRITE_COND)
    purple_cond |= PURPLE_INPUT_WRITE;

  closure->function(closure->data, g_io_channel_unix_get_fd(source),
                    static_cast<PurpleInputCondition>(purple_cond));

  return TRUE;
}

guint glib_input_add(gint fd, PurpleInputCondition condition,
                     PurpleInputFunction function, gpointer data) {
  PurpleGLibIOClosure *closure = g_new0(PurpleGLibIOClosure, 1);
  GIOChannel *channel;
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
  closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
                                        static_cast<GIOCondition>(cond),
                                        purple_glib_io_invoke, closure,
                                        purple_glib_io_destroy);

  g_io_channel_unref(channel);
  return closure->result;
}

PurpleEventLoopUiOps glib_eventloops = {
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

void purple_init(void) {
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

static gboolean io_callback(GIOChannel *io, GIOCondition condition,
                            gpointer p) {
  UNUSED(condition);
  PurpleConversation *conv = reinterpret_cast<PurpleConversation *>(p);
  gchar in;
  GError *error = NULL;
  static char buf[128];
  static int ind = 0;

  switch (g_io_channel_read_chars(io, &in, 1, NULL, &error)) {
  case G_IO_STATUS_NORMAL:
    buf[ind++] = in;
    if (ind == 128 || in == '\n') {
      buf[ind-1] = '\0';
      purple_conv_im_send(PURPLE_CONV_IM(conv), strdup(buf));
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

int main(void) {
  GMainLoop *loop = g_main_loop_new(NULL, FALSE);
  purple_init();
  std::string xmpp = "XMPP";
  GList *iter = purple_plugins_get_protocols();
  const char *prpl = NULL;
  for (; iter; iter = iter->next) {
    PurplePlugin *plugin = static_cast<PurplePlugin *>(iter->data);
    PurplePluginInfo *info = plugin->info;
    if (info && info->name && !strcmp(xmpp.c_str(), info->name)) {
      prpl = info->id;
      break;
    }
  }
  if (!prpl) {
    fprintf(stderr, "Failed to gets protocol.");
    abort();
  }

  printf("XMPP account: ");
  char name[128];
  char *res = fgets(name, sizeof(name), stdin);
  if (!res) {
    fprintf(stderr, "Failed to read user name.");
    abort();
  }
  name[strlen(name) - 1] = 0;  // strip the \n

  PurpleAccount *account = purple_account_new(name, prpl);
  char *password = getpass("Password: ");
  purple_account_set_password(account, password);
  purple_account_set_enabled(account, UI_ID, TRUE);

  PurpleSavedStatus *status = purple_savedstatus_new(NULL,
                                                     PURPLE_STATUS_AVAILABLE);
  purple_savedstatus_activate(status);
  connect_to_signals();
      
  printf("Buddy's XMPP account: ");
  char buddy[128];
  res = fgets(buddy, sizeof(buddy), stdin);
  if (!res) {
    fprintf(stderr, "Failed to read buddy's name.");
    abort();
  }
  buddy[strlen(buddy) - 1] = 0;  // strip the \n

  PurpleConversation *conv = purple_conversation_new(PURPLE_CONV_TYPE_IM,
                                                     account, buddy);

  GIOChannel *io = g_io_channel_unix_new(STDIN_FILENO);
  g_io_add_watch(io, G_IO_IN, io_callback, conv);
  g_main_loop_run(loop);

  return 0;
}
