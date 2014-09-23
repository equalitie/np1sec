

#include "internal.h"

#include "account.h"
#include "blist.h"
#include "conversation.h"
#include "debug.h"
#include "signals.h"
#include "status.h"
#include "version.h"
#include "privacy.h"

#include "plugin.h"
#include "pluginpref.h"
#include "prefs.h"


#define PLUGIN_ID       "core-psychic"
#define PLUGIN_NAME     N_("Psychic Mode")
#define PLUGIN_SUMMARY  N_("Psychic mode for incoming conversation")
#define PLUGIN_DESC     N_("Causes conversation windows to appear as other" \
			   " users begin to message you.  This works for" \
			   " AIM, ICQ, XMPP, Sametime, and Yahoo!")
#define PLUGIN_AUTHOR   "Christopher O'Brien <siege@preoccupied.net>"


#define PREFS_BASE    "/plugins/core/psychic"
#define PREF_BUDDIES  PREFS_BASE "/buddies_only"
#define PREF_NOTICE   PREFS_BASE "/show_notice"
#define PREF_STATUS   PREFS_BASE "/activate_online"
#define PREF_RAISE    PREFS_BASE "/raise_conv"


static void
buddy_typing_cb(PurpleAccount *acct, const char *name, void *data) {
  PurpleConversation *gconv;

  if(purple_prefs_get_bool(PREF_STATUS) &&
     ! purple_status_is_available(purple_account_get_active_status(acct))) {
    purple_debug_info("psychic", "not available, doing nothing\n");
    return;
  }

  if(purple_prefs_get_bool(PREF_BUDDIES) &&
     ! purple_find_buddy(acct, name)) {
    purple_debug_info("psychic", "not in blist, doing nothing\n");
    return;
  }

  if(FALSE == purple_privacy_check(acct, name)) {
    purple_debug_info("psychic", "user %s is blocked\n", name);
    return;
  }

  gconv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, acct);
  if(! gconv) {
    purple_debug_info("psychic", "no previous conversation exists\n");
    gconv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, name);

    if(purple_prefs_get_bool(PREF_RAISE)) {
      purple_conversation_present(gconv);
    }

    if(purple_prefs_get_bool(PREF_NOTICE)) {

      /* This is a quote from Star Wars.  You should probably not
	 translate it literally.  If you can't find a fitting cultural
	 reference in your language, consider translating something
	 like this instead: "You feel a new message coming." */
      purple_conversation_write(gconv, NULL,
			      _("You feel a disturbance in the force..."),
			      PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_ACTIVE_ONLY,
			      time(NULL));
    }

    /* Necessary because we may be creating a new conversation window. */
    purple_conv_im_set_typing_state(PURPLE_CONV_IM(gconv), PURPLE_TYPING);
  }
}


static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin) {

  PurplePluginPrefFrame *frame;
  PurplePluginPref *pref;

  frame = purple_plugin_pref_frame_new();

  pref = purple_plugin_pref_new_with_name(PREF_BUDDIES);
  purple_plugin_pref_set_label(pref, _("Only enable for users on"
				     " the buddy list"));
  purple_plugin_pref_frame_add(frame, pref);

  pref = purple_plugin_pref_new_with_name(PREF_STATUS);
  purple_plugin_pref_set_label(pref, _("Disable when away"));
  purple_plugin_pref_frame_add(frame, pref);

  pref = purple_plugin_pref_new_with_name(PREF_NOTICE);
  purple_plugin_pref_set_label(pref, _("Display notification message in"
				     " conversations"));
  purple_plugin_pref_frame_add(frame, pref);

  pref = purple_plugin_pref_new_with_name(PREF_RAISE);
  purple_plugin_pref_set_label(pref, _("Raise psychic conversations"));
  purple_plugin_pref_frame_add(frame, pref);

  return frame;
}


static gboolean
plugin_load(PurplePlugin *plugin) {

  void *convs_handle;
  convs_handle = purple_conversations_get_handle();

  purple_signal_connect(convs_handle, "buddy-typing", plugin,
		      PURPLE_CALLBACK(buddy_typing_cb), NULL);

  return TRUE;
}


static PurplePluginUiInfo prefs_info = {
  get_plugin_pref_frame,
  0,    /* page_num (Reserved) */
  NULL, /* frame (Reserved) */

  /* padding */
  NULL,
  NULL,
  NULL,
  NULL
};


static PurplePluginInfo info = {
  PURPLE_PLUGIN_MAGIC,
  PURPLE_MAJOR_VERSION,
  PURPLE_MINOR_VERSION,
  PURPLE_PLUGIN_STANDARD,   /**< type */
  NULL,                   /**< ui_requirement */
  0,                      /**< flags */
  NULL,                   /**< dependencies */
  PURPLE_PRIORITY_DEFAULT,  /**< priority */

  PLUGIN_ID,              /**< id */
  PLUGIN_NAME,            /**< name */
  DISPLAY_VERSION,        /**< version */
  PLUGIN_SUMMARY,         /**< summary */
  PLUGIN_DESC,            /**< description */
  PLUGIN_AUTHOR,          /**< author */
  PURPLE_WEBSITE,           /**< homepage */

  plugin_load,            /**< load */
  NULL,                   /**< unload */
  NULL,                   /**< destroy */

  NULL,                   /**< ui_info */
  NULL,                   /**< extra_info */
  &prefs_info,            /**< prefs_info */
  NULL,                   /**< actions */

  /* padding */
  NULL,
  NULL,
  NULL,
  NULL
};


static void
init_plugin(PurplePlugin *plugin) {
  purple_prefs_add_none(PREFS_BASE);
  purple_prefs_add_bool(PREF_BUDDIES, FALSE);
  purple_prefs_add_bool(PREF_NOTICE, TRUE);
  purple_prefs_add_bool(PREF_STATUS, TRUE);
}


PURPLE_INIT_PLUGIN(psychic, init_plugin, info)
