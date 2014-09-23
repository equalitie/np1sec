/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */

/* oscarcommon.h contains prototypes for the prpl functions used by libaim.c
 * and libicq.c
 */

#include "internal.h"

#include "accountopt.h"
#include "prpl.h"
#include "version.h"
#include "notify.h"
#include "status.h"

#define AIM_DEFAULT_LOGIN_SERVER "login.oscar.aol.com"
#define AIM_ALT_LOGIN_SERVER "login.messaging.aol.com"
#define AIM_DEFAULT_SSL_LOGIN_SERVER "slogin.oscar.aol.com"
#define ICQ_DEFAULT_LOGIN_SERVER "login.icq.com"
#define ICQ_DEFAULT_SSL_LOGIN_SERVER "slogin.icq.com"

#define OSCAR_DEFAULT_LOGIN_PORT 5190

#define OSCAR_OPPORTUNISTIC_ENCRYPTION "opportunistic_encryption"
#define OSCAR_REQUIRE_ENCRYPTION "require_encryption"
#define OSCAR_NO_ENCRYPTION "no_encryption"

#ifndef _WIN32
#define OSCAR_DEFAULT_CUSTOM_ENCODING "ISO-8859-1"
#else
#define OSCAR_DEFAULT_CUSTOM_ENCODING oscar_get_locale_charset()
#endif
#define OSCAR_DEFAULT_AUTHORIZATION TRUE
#define OSCAR_DEFAULT_HIDE_IP TRUE
#define OSCAR_DEFAULT_WEB_AWARE FALSE
#define OSCAR_DEFAULT_ALWAYS_USE_RV_PROXY FALSE
#define OSCAR_DEFAULT_ALLOW_MULTIPLE_LOGINS TRUE
#define OSCAR_DEFAULT_USE_CLIENTLOGIN TRUE
#define OSCAR_DEFAULT_ENCRYPTION OSCAR_OPPORTUNISTIC_ENCRYPTION

#ifdef _WIN32
const char *oscar_get_locale_charset(void);
#endif
PurpleMood* oscar_get_purple_moods(PurpleAccount *account);
const char *oscar_list_icon_icq(PurpleAccount *a, PurpleBuddy *b);
const char *oscar_list_icon_aim(PurpleAccount *a, PurpleBuddy *b);
const char* oscar_list_emblem(PurpleBuddy *b);
char *oscar_status_text(PurpleBuddy *b);
void oscar_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full);
GList *oscar_status_types(PurpleAccount *account);
GList *oscar_blist_node_menu(PurpleBlistNode *node);
GList *oscar_chat_info(PurpleConnection *gc);
GHashTable *oscar_chat_info_defaults(PurpleConnection *gc, const char *chat_name);
void oscar_login(PurpleAccount *account);
void oscar_close(PurpleConnection *gc);
int oscar_send_im(PurpleConnection *gc, const char *name, const char *message, PurpleMessageFlags imflags);
void oscar_set_info(PurpleConnection *gc, const char *rawinfo);
unsigned int oscar_send_typing(PurpleConnection *gc, const char *name, PurpleTypingState state);
void oscar_get_info(PurpleConnection *gc, const char *name);
void oscar_set_status(PurpleAccount *account, PurpleStatus *status);
void oscar_set_idle(PurpleConnection *gc, int time);
void oscar_change_passwd(PurpleConnection *gc, const char *old, const char *new);
void oscar_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group, const char *msg);
void oscar_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
void oscar_add_permit(PurpleConnection *gc, const char *who);
void oscar_add_deny(PurpleConnection *gc, const char *who);
void oscar_rem_permit(PurpleConnection *gc, const char *who);
void oscar_rem_deny(PurpleConnection *gc, const char *who);
void oscar_join_chat(PurpleConnection *gc, GHashTable *data);
char *oscar_get_chat_name(GHashTable *data);
void oscar_chat_invite(PurpleConnection *gc, int id, const char *message, const char *name);
void oscar_chat_leave(PurpleConnection *gc, int id);
int oscar_send_chat(PurpleConnection *gc, int id, const char *message, PurpleMessageFlags flags);
void oscar_keepalive(PurpleConnection *gc);
void oscar_alias_buddy(PurpleConnection *gc, const char *name, const char *alias);
void oscar_move_buddy(PurpleConnection *gc, const char *name, const char *old_group, const char *new_group);
void oscar_rename_group(PurpleConnection *gc, const char *old_name, PurpleGroup *group, GList *moved_buddies);
void oscar_convo_closed(PurpleConnection *gc, const char *who);
const char *oscar_normalize(const PurpleAccount *account, const char *str);
void oscar_set_icon(PurpleConnection *gc, PurpleStoredImage *img);
void oscar_remove_group(PurpleConnection *gc, PurpleGroup *group);
gboolean oscar_can_receive_file(PurpleConnection *gc, const char *who);
void oscar_send_file(PurpleConnection *gc, const char *who, const char *file);
PurpleXfer *oscar_new_xfer(PurpleConnection *gc, const char *who);
gboolean oscar_offline_message(const PurpleBuddy *buddy);
GList *oscar_actions(PurplePlugin *plugin, gpointer context);
void oscar_init(PurplePlugin *plugin, gboolean is_icq);
