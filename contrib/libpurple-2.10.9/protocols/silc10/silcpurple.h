/*

  silcpurple.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPURPLE_H
#define SILCPURPLE_H

/* Purple includes */
#include "internal.h"
#include "account.h"
#include "accountopt.h"
#include "cmds.h"
#include "conversation.h"
#include "debug.h"
#include "ft.h"
#include "notify.h"
#include "prpl.h"
#include "request.h"
#include "roomlist.h"
#include "server.h"
#include "util.h"

/* Default public and private key file names */
#define SILCPURPLE_PUBLIC_KEY_NAME "public_key.pub"
#define SILCPURPLE_PRIVATE_KEY_NAME "private_key.prv"

/* Default settings for creating key pair */
#define SILCPURPLE_DEF_PKCS "rsa"
#define SILCPURPLE_DEF_PKCS_LEN 2048

#define SILCPURPLE_PRVGRP 0x001fffff

/* Status IDs */
#define SILCPURPLE_STATUS_ID_OFFLINE	"offline"
#define SILCPURPLE_STATUS_ID_AVAILABLE "available"
#define SILCPURPLE_STATUS_ID_HYPER	"hyper"
#define SILCPURPLE_STATUS_ID_AWAY		"away"
#define SILCPURPLE_STATUS_ID_BUSY		"busy"
#define SILCPURPLE_STATUS_ID_INDISPOSED "indisposed"
#define SILCPURPLE_STATUS_ID_PAGE		"page"

typedef struct {
	unsigned long id;
	const char *channel;
	unsigned long chid;
	const char *parentch;
	SilcChannelPrivateKey key;
} *SilcPurplePrvgrp;

/* The SILC Purple plugin context */
typedef struct SilcPurpleStruct {
	SilcClient client;
	SilcClientConnection conn;

	guint scheduler;
	PurpleConnection *gc;
	PurpleAccount *account;
	unsigned long channel_ids;
	GList *grps;

	char *motd;
	PurpleRoomlist *roomlist;
#ifdef HAVE_SILCMIME_H
	SilcMimeAssembler mimeass;
#endif
	unsigned int detaching            : 1;
	unsigned int resuming             : 1;
	unsigned int roomlist_cancelled   : 1;
	unsigned int chpk                 : 1;
} *SilcPurple;


gboolean silcpurple_check_silc_dir(PurpleConnection *gc);
void silcpurple_chat_join_done(SilcClient client,
			     SilcClientConnection conn,
			     SilcClientEntry *clients,
			     SilcUInt32 clients_count,
			     void *context);
const char *silcpurple_silcdir(void);
const char *silcpurple_session_file(const char *account);
void silcpurple_verify_public_key(SilcClient client, SilcClientConnection conn,
				const char *name, SilcSocketType conn_type,
				unsigned char *pk, SilcUInt32 pk_len,
				SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context);
GList *silcpurple_buddy_menu(PurpleBuddy *buddy);
void silcpurple_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
void silcpurple_send_buddylist(PurpleConnection *gc);
void silcpurple_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);
void silcpurple_buddy_keyagr_request(SilcClient client,
				   SilcClientConnection conn,
				   SilcClientEntry client_entry,
				   const char *hostname, SilcUInt16 port);
void silcpurple_idle_set(PurpleConnection *gc, int idle);
void silcpurple_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full);
char *silcpurple_status_text(PurpleBuddy *b);
gboolean silcpurple_ip_is_private(const char *ip);
void silcpurple_ftp_send_file(PurpleConnection *gc, const char *name, const char *file);
PurpleXfer *silcpurple_ftp_new_xfer(PurpleConnection *gc, const char *name);
void silcpurple_ftp_request(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry client_entry, SilcUInt32 session_id,
			  const char *hostname, SilcUInt16 port);
void silcpurple_show_public_key(SilcPurple sg,
			      const char *name, SilcPublicKey public_key,
			      GCallback callback, void *context);
void silcpurple_get_info(PurpleConnection *gc, const char *who);
SilcAttributePayload
silcpurple_get_attr(SilcDList attrs, SilcAttribute attribute);
void silcpurple_get_umode_string(SilcUInt32 mode, char *buf,
			       SilcUInt32 buf_size);
void silcpurple_get_chmode_string(SilcUInt32 mode, char *buf,
				SilcUInt32 buf_size);
void silcpurple_get_chumode_string(SilcUInt32 mode, char *buf,
				 SilcUInt32 buf_size);
GList *silcpurple_chat_info(PurpleConnection *gc);
GHashTable *silcpurple_chat_info_defaults(PurpleConnection *gc, const char *chat_name);
GList *silcpurple_chat_menu(PurpleChat *);
void silcpurple_chat_join(PurpleConnection *gc, GHashTable *data);
char *silcpurple_get_chat_name(GHashTable *data);
void silcpurple_chat_invite(PurpleConnection *gc, int id, const char *msg,
			  const char *name);
void silcpurple_chat_leave(PurpleConnection *gc, int id);
int silcpurple_chat_send(PurpleConnection *gc, int id, const char *msg, PurpleMessageFlags flags);
void silcpurple_chat_set_topic(PurpleConnection *gc, int id, const char *topic);
PurpleRoomlist *silcpurple_roomlist_get_list(PurpleConnection *gc);
void silcpurple_roomlist_cancel(PurpleRoomlist *list);
void silcpurple_chat_chauth_show(SilcPurple sg, SilcChannelEntry channel,
			       SilcBuffer channel_pubkeys);
void silcpurple_parse_attrs(SilcDList attrs, char **moodstr, char **statusstr,
					 char **contactstr, char **langstr, char **devicestr,
					 char **tzstr, char **geostr);
#ifdef SILC_ATTRIBUTE_USER_ICON
void silcpurple_buddy_set_icon(PurpleConnection *gc, PurpleStoredImage *img);
#endif
#ifdef HAVE_SILCMIME_H
char *silcpurple_file2mime(const char *filename);
SilcDList silcpurple_image_message(const char *msg, SilcUInt32 *mflags);
#endif

#ifdef _WIN32
typedef int uid_t;

struct passwd {
	char	*pw_name;	/* user name */
	char	*pw_passwd;	/* user password */
	int		pw_uid;		/* user id */
	int		pw_gid;		/* group id */
	char	*pw_gecos;	/* real name */
	char	*pw_dir;	/* home directory */
	char	*pw_shell;	/* shell program */
};

struct passwd *getpwuid(int uid);
int getuid(void);
int geteuid(void);
#endif

#endif /* SILCPURPLE_H */
