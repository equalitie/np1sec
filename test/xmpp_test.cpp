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
  #include "purple.h"
}

#define CUSTOM_USER_DIRECTORY "/tmp/test_user"
#define CUSTOM_PLUGIN_PATH ""
#define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
#define UI_ID "test_client"

void write_conv(PurpleConversation *conv, const char *who, const char *alias,
                const char *message, PurpleMessageFlags flags, time_t mtime) {
  const char *name;
  if (alias && *alias)
    name = alias;
  else if (who && *who)
    name = who;
  else
    name = NULL;

  printf("(%s) %s %s: %s\n", purple_conversation_get_name(conv),
         purple_utf8_strftime("(%H:%M:%S)", localtime(&mtime)),
         name, message);
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
  PurpleAccount *account = purple_connection_get_account(gc);
  printf("Account connected: %s %s\n", account->username, account->protocol_id);
}

static void connect_to_signals_for_demonstration_purposes_only(void) {
  static int handle;
  purple_signal_connect(purple_connections_get_handle(), "signed-on", &handle,
                        PURPLE_CALLBACK(signed_on), NULL);
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
  printf("loading libpurple ...\n");

  purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
  purple_debug_set_enabled(TRUE);
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

  printf("initializing libpurple succeeded\n");
}

int main(int argc, char **argv) {
  GList *iter;
  int i, num;
  GList *names = NULL;
  const char *prpl = NULL;
  char name[128];
  char *password;
  GMainLoop *loop = g_main_loop_new(NULL, FALSE);
  PurpleAccount *account;
  PurpleSavedStatus *status;
  char *res;


  purple_init();

  iter = purple_plugins_get_protocols();
  for (i = 0; iter; iter = iter->next) {
    PurplePlugin *plugin = static_cast<PurplePlugin *>(iter->data);
    PurplePluginInfo *info = plugin->info;
    if (info && info->name) {
      printf("\t%d: %s\n", i++, info->name);
      names = g_list_append(names, info->id);
    }
  }

  printf("Select the protocol [0-%d]: ", i-1);
  res = fgets(name, sizeof(name), stdin);
  if (!res) {
    fprintf(stderr, "Failed to gets protocol selection.");
    abort();
  }
  if (sscanf(name, "%d", &num) == 1)
    prpl = (const char *)g_list_nth_data(names, num);
  if (!prpl) {
    fprintf(stderr, "Failed to gets protocol.");
    abort();
  }

  printf("Username: ");
  res = fgets(name, sizeof(name), stdin);
  if (!res) {
    fprintf(stderr, "Failed to read user name.");
    abort();
  }
  name[strlen(name) - 1] = 0;  /* strip the \n at the end */

  /* Create the account */
  account = purple_account_new(name, prpl);

  /* Get the password for the account */
  password = getpass("Password: ");
  purple_account_set_password(account, password);

  /* It's necessary to enable the account first. */
  purple_account_set_enabled(account, UI_ID, TRUE);

  /* Now, to connect the account(s), create a status and activate it. */
  status = purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE);
  purple_savedstatus_activate(status);

  connect_to_signals_for_demonstration_purposes_only();

  g_main_loop_run(loop);

  return 0;
}
