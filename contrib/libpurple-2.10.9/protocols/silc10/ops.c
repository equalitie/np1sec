/*

  silcpurple_ops.c

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

#include "silcincludes.h"
#include "silcclient.h"
#include "silcpurple.h"
#include "imgstore.h"
#include "wb.h"

static void
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessagePayload payload, SilcChannelPrivateKey key,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len);
static void
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessagePayload payload,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len);

/* Message sent to the application by library. `conn' associates the
   message to a specific connection.  `conn', however, may be NULL.
   The `type' indicates the type of the message sent by the library.
   The application can for example filter the message according the
   type. */

static void
silc_say(SilcClient client, SilcClientConnection conn,
	 SilcClientMessageType type, char *msg, ...)
{
	/* Nothing */
}

#ifdef HAVE_SILCMIME_H
/* Processes incoming MIME message.  Can be private message or channel
   message. */

static void
silcpurple_mime_message(SilcClient client, SilcClientConnection conn,
		      SilcClientEntry sender, SilcChannelEntry channel,
		      SilcMessagePayload payload, SilcChannelPrivateKey key,
		      SilcMessageFlags flags, SilcMime mime,
		      gboolean recursive)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	const char *type;
	const unsigned char *data;
	SilcUInt32 data_len;
	PurpleMessageFlags cflags = 0;
	PurpleConversation *convo = NULL;

	if (!mime)
		return;

	/* Check for fragmented MIME message */
	if (silc_mime_is_partial(mime)) {
		if (!sg->mimeass)
			sg->mimeass = silc_mime_assembler_alloc();

		/* Defragment */
		mime = silc_mime_assemble(sg->mimeass, mime);
		if (!mime)
			/* More fragments to come */
			return;

		/* Process the complete message */
		silcpurple_mime_message(client, conn, sender, channel,
				      payload, key, flags, mime, FALSE);
		return;
	}

	/* Check for multipart message */
	if (silc_mime_is_multipart(mime)) {
		SilcMime p;
		const char *mtype;
		SilcDList parts = silc_mime_get_multiparts(mime, &mtype);

		/* Only "mixed" type supported */
		if (strcmp(mtype, "mixed"))
			goto out;

		silc_dlist_start(parts);
		while ((p = silc_dlist_get(parts)) != SILC_LIST_END) {
			/* Recursively process parts */
			silcpurple_mime_message(client, conn, sender, channel,
					      payload, key, flags, p, TRUE);
		}
		goto out;
	}

	/* Get content type and MIME data */
	type = silc_mime_get_field(mime, "Content-Type");
	if (!type)
		goto out;
	data = silc_mime_get_data(mime, &data_len);
	if (!data)
		goto out;

	/* Process according to content type */

	/* Plain text */
	if (strstr(type, "text/plain")) {
		/* Default is UTF-8, don't check for other charsets */
		if (!strstr(type, "utf-8"))
			goto out;

		if (channel)
			silc_channel_message(client, conn, sender, channel,
					     payload, key,
					     SILC_MESSAGE_FLAG_UTF8, data,
					     data_len);
		else
			silc_private_message(client, conn, sender, payload,
					     SILC_MESSAGE_FLAG_UTF8, data,
					     data_len);
		goto out;
	}

	/* Image */
	if (strstr(type, "image/png") ||
	    strstr(type, "image/jpeg") ||
	    strstr(type, "image/gif") ||
	    strstr(type, "image/tiff")) {
		char tmp[32];
		int imgid;

		/* Get channel convo (if message is for channel) */
		if (key && channel) {
			GList *l;
			SilcPurplePrvgrp prv;

			for (l = sg->grps; l; l = l->next)
				if (((SilcPurplePrvgrp)l->data)->key == key) {
					prv = l->data;
					convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
							prv->channel, sg->account);
					break;
				}
		}
		if (channel && !convo)
			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								    channel->channel_name, sg->account);
		if (channel && !convo)
			goto out;

		imgid = purple_imgstore_add_with_id(g_memdup(data, data_len), data_len, "");
		if (imgid) {
			cflags |= PURPLE_MESSAGE_IMAGES | PURPLE_MESSAGE_RECV;
			g_snprintf(tmp, sizeof(tmp), "<IMG ID=\"%d\">", imgid);

			if (channel)
				serv_got_chat_in(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)),
				 		 sender->nickname ?
				 		  sender->nickname :
						 "<unknown>", cflags,
						 tmp, time(NULL));
			else
				serv_got_im(gc, sender->nickname ?
					    sender->nickname : "<unknown>",
					    tmp, cflags, time(NULL));

			purple_imgstore_unref_by_id(imgid);
			cflags = 0;
		}
		goto out;
	}

	/* Whiteboard message */
	if (strstr(type, "application/x-wb") &&
	    !purple_account_get_bool(sg->account, "block-wb", FALSE)) {
		if (channel)
			silcpurple_wb_receive_ch(client, conn, sender, channel,
					       payload, flags, data, data_len);
		else
			silcpurple_wb_receive(client, conn, sender, payload,
					    flags, data, data_len);
		goto out;
	}

 out:
	if (!recursive)
		silc_mime_free(mime);
}
#endif /* HAVE_SILCMIME_H */

/* Message for a channel. The `sender' is the sender of the message
   The `channel' is the channel. The `message' is the message.  Note
   that `message' maybe NULL.  The `flags' indicates message flags
   and it is used to determine how the message can be interpreted
   (like it may tell the message is multimedia message). */

static void
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessagePayload payload, SilcChannelPrivateKey key,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	PurpleConversation *convo = NULL;
	char *msg, *tmp;

	if (!message)
		return;

	if (key) {
		GList *l;
		SilcPurplePrvgrp prv;

		for (l = sg->grps; l; l = l->next)
			if (((SilcPurplePrvgrp)l->data)->key == key) {
				prv = l->data;
				convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
										prv->channel, sg->account);
				break;
			}
	}
	if (!convo)
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								channel->channel_name, sg->account);
	if (!convo)
		return;

	if (flags & SILC_MESSAGE_FLAG_SIGNED &&
	    purple_account_get_bool(sg->account, "sign-verify", FALSE)) {
		/* XXX */
	}

	if (flags & SILC_MESSAGE_FLAG_DATA) {
		/* Process MIME message */
#ifdef HAVE_SILCMIME_H
		SilcMime mime;
		mime = silc_mime_decode(message, message_len);
		silcpurple_mime_message(client, conn, sender, channel, payload,
				      key, flags, mime, FALSE);
#else
		char type[128], enc[128];
		unsigned char *data;
		SilcUInt32 data_len;

		memset(type, 0, sizeof(type));
		memset(enc, 0, sizeof(enc));

		if (!silc_mime_parse(message, message_len, NULL, 0,
		    type, sizeof(type) - 1, enc, sizeof(enc) - 1, &data,
		    &data_len))
			return;

		if (!strcmp(type, "application/x-wb") &&
		    !strcmp(enc, "binary") &&
		    !purple_account_get_bool(sg->account, "block-wb", FALSE))
			silcpurple_wb_receive_ch(client, conn, sender, channel,
					       payload, flags, data, data_len);
#endif
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_ACTION) {
		msg = g_strdup_printf("/me %s",
				      (const char *)message);
		if (!msg)
			return;

		tmp = g_markup_escape_text(msg, -1);
		/* Send to Purple */
		serv_got_chat_in(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)),
				 sender->nickname ?
				 sender->nickname : "<unknown>", 0,
				 tmp, time(NULL));
		g_free(tmp);
		g_free(msg);
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_NOTICE) {
		msg = g_strdup_printf("(notice) <I>%s</I> %s",
				      sender->nickname ?
				      sender->nickname : "<unknown>",
				      (const char *)message);
		if (!msg)
			return;

		/* Send to Purple */
		purple_conversation_write(convo, NULL, (const char *)msg,
					PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(msg);
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_UTF8) {
		tmp = g_markup_escape_text((const char *)message, -1);
		/* Send to Purple */
		serv_got_chat_in(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)),
				 sender->nickname ?
				 sender->nickname : "<unknown>", 0,
				 tmp, time(NULL));
		g_free(tmp);
	}
}


/* Private message to the client. The `sender' is the sender of the
   message. The message is `message'and maybe NULL.  The `flags'
   indicates message flags  and it is used to determine how the message
   can be interpreted (like it may tell the message is multimedia
   message). */

static void
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessagePayload payload,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	PurpleConversation *convo = NULL;
	char *msg, *tmp;

	if (!message)
		return;

	if (sender->nickname)
		/* XXX - Should this be PURPLE_CONV_TYPE_IM? */
		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
								sender->nickname, sg->account);

	if (flags & SILC_MESSAGE_FLAG_SIGNED &&
	    purple_account_get_bool(sg->account, "sign-verify", FALSE)) {
		/* XXX */
	}

	if (flags & SILC_MESSAGE_FLAG_DATA) {
#ifdef HAVE_SILCMIME_H
		/* Process MIME message */
		SilcMime mime;
		mime = silc_mime_decode(message, message_len);
		silcpurple_mime_message(client, conn, sender, NULL, payload,
				      NULL, flags, mime, FALSE);
#else
		char type[128], enc[128];
		unsigned char *data;
		SilcUInt32 data_len;

		memset(type, 0, sizeof(type));
		memset(enc, 0, sizeof(enc));

		if (!silc_mime_parse(message, message_len, NULL, 0,
		    type, sizeof(type) - 1, enc, sizeof(enc) - 1, &data,
		    &data_len))
			return;

		if (!strcmp(type, "application/x-wb") &&
		    !strcmp(enc, "binary") &&
		    !purple_account_get_bool(sg->account, "block-wb", FALSE))
			silcpurple_wb_receive(client, conn, sender, payload,
					    flags, data, data_len);
#endif
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_ACTION && convo) {
		msg = g_strdup_printf("/me %s",
				      (const char *)message);
		if (!msg)
			return;

		tmp = g_markup_escape_text(msg, -1);
		/* Send to Purple */
		serv_got_im(gc, sender->nickname ?
			    sender->nickname : "<unknown>",
			    tmp, 0, time(NULL));
		g_free(msg);
		g_free(tmp);
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_NOTICE && convo) {
		msg = g_strdup_printf("(notice) <I>%s</I> %s",
				      sender->nickname ?
				      sender->nickname : "<unknown>",
				      (const char *)message);
		if (!msg)
			return;

		/* Send to Purple */
		purple_conversation_write(convo, NULL, (const char *)msg,
					PURPLE_MESSAGE_SYSTEM, time(NULL));
		g_free(msg);
		return;
	}

	if (flags & SILC_MESSAGE_FLAG_UTF8) {
		tmp = g_markup_escape_text((const char *)message, -1);
		/* Send to Purple */
		serv_got_im(gc, sender->nickname ?
			    sender->nickname : "<unknown>",
			    tmp, 0, time(NULL));
		g_free(tmp);
	}
}


/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it because client library gets the channel entry from
   the Channel ID in the packet's header). */

static void
silc_notify(SilcClient client, SilcClientConnection conn,
	    SilcNotifyType type, ...)
{
	va_list va;
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	PurpleConversation *convo;
	SilcClientEntry client_entry, client_entry2;
	SilcChannelEntry channel;
	SilcServerEntry server_entry;
	SilcIdType idtype;
	void *entry;
	SilcUInt32 mode;
	SilcHashTableList htl;
	SilcChannelUser chu;
	char buf[512], buf2[512], *tmp, *name;
	SilcNotifyType notify;
	PurpleBuddy *b;
	int i;

	va_start(va, type);
	memset(buf, 0, sizeof(buf));

	switch (type) {

	case SILC_NOTIFY_TYPE_NONE:
		break;

	case SILC_NOTIFY_TYPE_INVITE:
		{
			GHashTable *components;
			va_arg(va, SilcChannelEntry);
			name = va_arg(va, char *);
			client_entry = va_arg(va, SilcClientEntry);

			components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
			g_hash_table_insert(components, strdup("channel"), strdup(name));
			serv_got_chat_invite(gc, name, client_entry->nickname, NULL, components);
		}
		break;

	case SILC_NOTIFY_TYPE_JOIN:
		client_entry = va_arg(va, SilcClientEntry);
		channel = va_arg(va, SilcChannelEntry);

		/* If we joined channel, do nothing */
		if (client_entry == conn->local_entry)
			break;

		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								channel->channel_name, sg->account);
		if (!convo)
			break;

		/* Join user to channel */
		g_snprintf(buf, sizeof(buf), "%s@%s",
			   client_entry->username, client_entry->hostname);
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(convo),
					g_strdup(client_entry->nickname), buf, PURPLE_CBFLAGS_NONE, TRUE);

		break;

	case SILC_NOTIFY_TYPE_LEAVE:
		client_entry = va_arg(va, SilcClientEntry);
		channel = va_arg(va, SilcChannelEntry);

		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								channel->channel_name, sg->account);
		if (!convo)
			break;

		/* Remove user from channel */
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo),
					   client_entry->nickname, NULL);

		break;

	case SILC_NOTIFY_TYPE_SIGNOFF:
		client_entry = va_arg(va, SilcClientEntry);
		tmp = va_arg(va, char *);

		if (!client_entry->nickname)
			break;

		/* Remove from all channels */
		silc_hash_table_list(client_entry->channels, &htl);
		while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									chu->channel->channel_name, sg->account);
			if (!convo)
				continue;
			purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo),
						   client_entry->nickname,
						   tmp);
		}
		silc_hash_table_list_reset(&htl);

		break;

	case SILC_NOTIFY_TYPE_TOPIC_SET:
		{
			char *esc, *tmp2;
			idtype = va_arg(va, int);
			entry = va_arg(va, void *);
			tmp = va_arg(va, char *);
			channel = va_arg(va, SilcChannelEntry);

			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									channel->channel_name, sg->account);
			if (!convo)
				break;

			if (!tmp)
				break;

			esc = g_markup_escape_text(tmp, -1);
			tmp2 = purple_markup_linkify(esc);
			g_free(esc);

			if (idtype == SILC_ID_CLIENT) {
				client_entry = (SilcClientEntry)entry;
				g_snprintf(buf, sizeof(buf),
						_("%s has changed the topic of <I>%s</I> to: %s"),
						client_entry->nickname, channel->channel_name, tmp2);
				purple_conv_chat_write(PURPLE_CONV_CHAT(convo), client_entry->nickname,
						buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
				purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo),
						client_entry->nickname, tmp);
			} else if (idtype == SILC_ID_SERVER) {
				server_entry = (SilcServerEntry)entry;
				g_snprintf(buf, sizeof(buf),
						_("%s has changed the topic of <I>%s</I> to: %s"),
						server_entry->server_name, channel->channel_name, tmp2);
				purple_conv_chat_write(PURPLE_CONV_CHAT(convo), server_entry->server_name,
						buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
				purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo),
						server_entry->server_name, tmp);
			} else if (idtype == SILC_ID_CHANNEL) {
				channel = (SilcChannelEntry)entry;
				g_snprintf(buf, sizeof(buf),
						_("%s has changed the topic of <I>%s</I> to: %s"),
						channel->channel_name, channel->channel_name, tmp2);
				purple_conv_chat_write(PURPLE_CONV_CHAT(convo), channel->channel_name,
						buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
				purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo),
						channel->channel_name, tmp);
			} else {
				purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo), NULL, tmp);
			}

			g_free(tmp2);

			break;

		}
	case SILC_NOTIFY_TYPE_NICK_CHANGE:
		client_entry = va_arg(va, SilcClientEntry);
		client_entry2 = va_arg(va, SilcClientEntry);

		if (!strcmp(client_entry->nickname, client_entry2->nickname))
			break;

		/* Change nick on all channels */
		silc_hash_table_list(client_entry2->channels, &htl);
		while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									chu->channel->channel_name, sg->account);
			if (!convo)
				continue;
			if (purple_conv_chat_find_user(PURPLE_CONV_CHAT(convo), client_entry->nickname))
				purple_conv_chat_rename_user(PURPLE_CONV_CHAT(convo),
										   client_entry->nickname,
										   client_entry2->nickname);
		}
		silc_hash_table_list_reset(&htl);

		break;

	case SILC_NOTIFY_TYPE_CMODE_CHANGE:
		idtype = va_arg(va, int);
		entry = va_arg(va, void *);
		mode = va_arg(va, SilcUInt32);
		(void)va_arg(va, char *);
		(void)va_arg(va, char *);
		(void)va_arg(va, char *);
		(void)va_arg(va, SilcPublicKey);
		(void)va_arg(va, SilcBuffer);
		channel = va_arg(va, SilcChannelEntry);

		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								channel->channel_name, sg->account);
		if (!convo)
			break;

		if (idtype == SILC_ID_CLIENT)
			name = ((SilcClientEntry)entry)->nickname;
		else if (idtype == SILC_ID_SERVER)
			name = ((SilcServerEntry)entry)->server_name;
		else
			name = ((SilcChannelEntry)entry)->channel_name;
		if (!name)
			break;

		if (mode) {
			silcpurple_get_chmode_string(mode, buf2, sizeof(buf2));
			g_snprintf(buf, sizeof(buf),
				   _("<I>%s</I> set channel <I>%s</I> modes to: %s"), name,
				   channel->channel_name, buf2);
		} else {
			g_snprintf(buf, sizeof(buf),
				   _("<I>%s</I> removed all channel <I>%s</I> modes"), name,
				   channel->channel_name);
		}
		purple_conv_chat_write(PURPLE_CONV_CHAT(convo), channel->channel_name,
				     buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
		break;

	case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
		{
			PurpleConvChatBuddyFlags flags = PURPLE_CBFLAGS_NONE;
			idtype = va_arg(va, int);
			entry = va_arg(va, void *);
			mode = va_arg(va, SilcUInt32);
			client_entry2 = va_arg(va, SilcClientEntry);
			channel = va_arg(va, SilcChannelEntry);

			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									channel->channel_name, sg->account);
			if (!convo)
				break;

			if (idtype == SILC_ID_CLIENT)
				name = ((SilcClientEntry)entry)->nickname;
			else if (idtype == SILC_ID_SERVER)
				name = ((SilcServerEntry)entry)->server_name;
			else
				name = ((SilcChannelEntry)entry)->channel_name;
			if (!name)
				break;

			if (mode) {
				silcpurple_get_chumode_string(mode, buf2, sizeof(buf2));
				g_snprintf(buf, sizeof(buf),
						_("<I>%s</I> set <I>%s's</I> modes to: %s"), name,
						client_entry2->nickname, buf2);
				if (mode & SILC_CHANNEL_UMODE_CHANFO)
					flags |= PURPLE_CBFLAGS_FOUNDER;
				if (mode & SILC_CHANNEL_UMODE_CHANOP)
					flags |= PURPLE_CBFLAGS_OP;
			} else {
				g_snprintf(buf, sizeof(buf),
						_("<I>%s</I> removed all <I>%s's</I> modes"), name,
						client_entry2->nickname);
			}
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), channel->channel_name,
					buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
			purple_conv_chat_user_set_flags(PURPLE_CONV_CHAT(convo), client_entry2->nickname, flags);
			break;
		}

	case SILC_NOTIFY_TYPE_MOTD:
		tmp = va_arg(va, char *);
		silc_free(sg->motd);
		sg->motd = silc_memdup(tmp, strlen(tmp));
		break;

	case SILC_NOTIFY_TYPE_KICKED:
		client_entry = va_arg(va, SilcClientEntry);
		tmp = va_arg(va, char *);
		client_entry2 = va_arg(va, SilcClientEntry);
		channel = va_arg(va, SilcChannelEntry);

		convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								channel->channel_name, sg->account);
		if (!convo)
			break;

		if (client_entry == conn->local_entry) {
			/* Remove us from channel */
			g_snprintf(buf, sizeof(buf),
				   _("You have been kicked off <I>%s</I> by <I>%s</I> (%s)"),
				   channel->channel_name, client_entry2->nickname,
				   tmp ? tmp : "");
			purple_conv_chat_write(PURPLE_CONV_CHAT(convo), client_entry->nickname,
					     buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
			serv_got_chat_left(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)));
		} else {
			/* Remove user from channel */
			g_snprintf(buf, sizeof(buf), _("Kicked by %s (%s)"),
				   client_entry2->nickname, tmp ? tmp : "");
			purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo),
						   client_entry->nickname,
						   buf);
		}

		break;

	case SILC_NOTIFY_TYPE_KILLED:
		client_entry = va_arg(va, SilcClientEntry);
		tmp = va_arg(va, char *);
		idtype = va_arg(va, int);
		entry = va_arg(va, SilcClientEntry);

		if (!client_entry->nickname)
			break;

		if (client_entry == conn->local_entry) {
			if (idtype == SILC_ID_CLIENT) {
				client_entry2 = (SilcClientEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("You have been killed by %s (%s)"),
					   client_entry2->nickname, tmp ? tmp : "");
			} else if (idtype == SILC_ID_SERVER) {
				server_entry = (SilcServerEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("You have been killed by %s (%s)"),
					   server_entry->server_name, tmp ? tmp : "");
			} else if (idtype == SILC_ID_CHANNEL) {
				channel = (SilcChannelEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("You have been killed by %s (%s)"),
					   channel->channel_name, tmp ? tmp : "");
			}

			/* Remove us from all channels */
			silc_hash_table_list(client_entry->channels, &htl);
			while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
				convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
										chu->channel->channel_name, sg->account);
				if (!convo)
					continue;
				purple_conv_chat_write(PURPLE_CONV_CHAT(convo), client_entry->nickname,
						     buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
				serv_got_chat_left(gc, purple_conv_chat_get_id(PURPLE_CONV_CHAT(convo)));
			}
			silc_hash_table_list_reset(&htl);

		} else {
			if (idtype == SILC_ID_CLIENT) {
				client_entry2 = (SilcClientEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("Killed by %s (%s)"),
					   client_entry2->nickname, tmp ? tmp : "");
			} else if (idtype == SILC_ID_SERVER) {
				server_entry = (SilcServerEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("Killed by %s (%s)"),
					   server_entry->server_name, tmp ? tmp : "");
			} else if (idtype == SILC_ID_CHANNEL) {
				channel = (SilcChannelEntry)entry;
				g_snprintf(buf, sizeof(buf),
					   _("Killed by %s (%s)"),
					   channel->channel_name, tmp ? tmp : "");
			}

			/* Remove user from all channels */
			silc_hash_table_list(client_entry->channels, &htl);
			while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
				convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
										chu->channel->channel_name, sg->account);
				if (!convo)
					continue;
				purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo),
							   client_entry->nickname, tmp);
			}
			silc_hash_table_list_reset(&htl);
		}

		break;

	case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
		break;

	case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
		{
			int i;
			SilcClientEntry *clients;
			SilcUInt32 clients_count;

			(void)va_arg(va, void *);
			clients = va_arg(va, SilcClientEntry *);
			clients_count = va_arg(va, SilcUInt32);

			for (i = 0; i < clients_count; i++) {
				if (!clients[i]->nickname)
					break;

				/* Remove from all channels */
				silc_hash_table_list(clients[i]->channels, &htl);
				while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
					convo =
						purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
											chu->channel->channel_name, sg->account);
					if (!convo)
						continue;
					purple_conv_chat_remove_user(PURPLE_CONV_CHAT(convo),
								   clients[i]->nickname,
								   _("Server signoff"));
				}
				silc_hash_table_list_reset(&htl);
			}
		}
		break;

	case SILC_NOTIFY_TYPE_ERROR:
		{
			SilcStatus error = va_arg(va, int);
			purple_notify_error(gc, "Error Notify",
					  silc_get_status_message(error),
					  NULL);
		}
		break;

	case SILC_NOTIFY_TYPE_WATCH:
		{
			SilcPublicKey public_key;
			unsigned char *pk;
			SilcUInt32 pk_len;
			char *fingerprint;

			client_entry = va_arg(va, SilcClientEntry);
			(void)va_arg(va, char *);
			mode = va_arg(va, SilcUInt32);
			notify = va_arg(va, int);
			public_key = va_arg(va, SilcPublicKey);

			b = NULL;
			if (public_key) {
				PurpleBlistNode *gnode, *cnode, *bnode;
				const char *f;

				pk = silc_pkcs_public_key_encode(public_key, &pk_len);
				if (!pk)
					break;
				fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
				for (i = 0; i < strlen(fingerprint); i++)
					if (fingerprint[i] == ' ')
						fingerprint[i] = '_';
				g_snprintf(buf, sizeof(buf) - 1,
					   "%s" G_DIR_SEPARATOR_S "clientkeys"
					   G_DIR_SEPARATOR_S "clientkey_%s.pub",
					   silcpurple_silcdir(), fingerprint);
				silc_free(fingerprint);
				silc_free(pk);

				/* Find buddy by associated public key */
				for (gnode = purple_get_blist()->root; gnode;
				     gnode = gnode->next) {
					if (!PURPLE_BLIST_NODE_IS_GROUP(gnode))
						continue;
					for (cnode = gnode->child; cnode; cnode = cnode->next) {
						if( !PURPLE_BLIST_NODE_IS_CONTACT(cnode))
							continue;
						for (bnode = cnode->child; bnode;
						     bnode = bnode->next) {
							if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
								continue;
							b = (PurpleBuddy *)bnode;
							if (b->account != gc->account)
								continue;
							f = purple_blist_node_get_string(bnode, "public-key");
							if (f && !strcmp(f, buf))
								goto cont;
							b = NULL;
						}
					}
				}
			}
		cont:
			if (!b) {
				/* Find buddy by nickname */
				b = purple_find_buddy(sg->account, client_entry->nickname);
				if (!b) {
					purple_debug_warning("silc", "WATCH for %s, unknown buddy\n",
						client_entry->nickname);
					break;
				}
			}

			silc_free(b->proto_data);
			b->proto_data = silc_memdup(client_entry->id,
						    sizeof(*client_entry->id));
			if (notify == SILC_NOTIFY_TYPE_NICK_CHANGE) {
				break;
			} else if (notify == SILC_NOTIFY_TYPE_UMODE_CHANGE) {
				/* See if client was away and is now present */
				if (!(mode & (SILC_UMODE_GONE | SILC_UMODE_INDISPOSED |
					      SILC_UMODE_BUSY | SILC_UMODE_PAGE |
					      SILC_UMODE_DETACHED)) &&
				    (client_entry->mode & SILC_UMODE_GONE ||
				     client_entry->mode & SILC_UMODE_INDISPOSED ||
				     client_entry->mode & SILC_UMODE_BUSY ||
				     client_entry->mode & SILC_UMODE_PAGE ||
				     client_entry->mode & SILC_UMODE_DETACHED)) {
					client_entry->mode = mode;
					purple_prpl_got_user_status(purple_buddy_get_account(b), purple_buddy_get_name(b), SILCPURPLE_STATUS_ID_AVAILABLE, NULL);
				}
				else if ((mode & SILC_UMODE_GONE) ||
					 (mode & SILC_UMODE_INDISPOSED) ||
					 (mode & SILC_UMODE_BUSY) ||
					 (mode & SILC_UMODE_PAGE) ||
					 (mode & SILC_UMODE_DETACHED)) {
					client_entry->mode = mode;
					purple_prpl_got_user_status(purple_buddy_get_account(b), purple_buddy_get_name(b), SILCPURPLE_STATUS_ID_OFFLINE, NULL);
				}
			} else if (notify == SILC_NOTIFY_TYPE_SIGNOFF ||
				   notify == SILC_NOTIFY_TYPE_SERVER_SIGNOFF ||
				   notify == SILC_NOTIFY_TYPE_KILLED) {
				client_entry->mode = mode;
				purple_prpl_got_user_status(purple_buddy_get_account(b), purple_buddy_get_name(b), SILCPURPLE_STATUS_ID_OFFLINE, NULL);
			} else if (notify == SILC_NOTIFY_TYPE_NONE) {
				client_entry->mode = mode;
				purple_prpl_got_user_status(purple_buddy_get_account(b), purple_buddy_get_name(b), SILCPURPLE_STATUS_ID_AVAILABLE, NULL);
			}
		}
		break;

	default:
		purple_debug_info("silc", "Unhandled notification: %d\n", type);
		break;
	}

	va_end(va);
}


/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occurred
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

static void
silc_command(SilcClient client, SilcClientConnection conn,
	     SilcClientCommandContext cmd_context, bool success,
	     SilcCommand command, SilcStatus status)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;

	switch (command) {

	case SILC_COMMAND_CMODE:
		if (cmd_context->argc == 3 &&
		    !strcmp((char *)cmd_context->argv[2], "+C"))
			sg->chpk = TRUE;
		else
			sg->chpk = FALSE;
		break;

	default:
		break;
	}
}

#if 0
static void
silcpurple_whois_more(SilcClientEntry client_entry, gint id)
{
	SilcAttributePayload attr;
	SilcAttribute attribute;
	char *buf;
	GString *s;
	SilcVCardStruct vcard;
	int i;

	if (id != 0)
		return;

	memset(&vcard, 0, sizeof(vcard));

	s = g_string_new("");

	silc_dlist_start(client_entry->attrs);
	while ((attr = silc_dlist_get(client_entry->attrs)) != SILC_LIST_END) {
		attribute = silc_attribute_get_attribute(attr);
		switch (attribute) {

		case SILC_ATTRIBUTE_USER_INFO:
			if (!silc_attribute_get_object(attr, (void *)&vcard,
						       sizeof(vcard)))
				continue;
			g_string_append_printf(s, "%s:\n\n", _("Personal Information"));
			if (vcard.full_name)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Full Name"),
						       vcard.full_name);
			if (vcard.first_name)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("First Name"),
						       vcard.first_name);
			if (vcard.middle_names)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("Middle Name"),
						       vcard.middle_names);
			if (vcard.family_name)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("Family Name"),
						       vcard.family_name);
			if (vcard.nickname)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Nickname"),
						       vcard.nickname);
			if (vcard.bday)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Birth Day"),
						       vcard.bday);
			if (vcard.title)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Job Title"),
						       vcard.title);
			if (vcard.role)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Job Role"),
						       vcard.role);
			if (vcard.org_name)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("Organization"),
						       vcard.org_name);
			if (vcard.org_unit)
				g_string_append_printf(s, "%s:\t\t%s\n",
						       _("Unit"),
						       vcard.org_unit);
			if (vcard.url)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("Homepage"),
						       vcard.url);
			if (vcard.label)
				g_string_append_printf(s, "%s:\t%s\n",
						       _("Address"),
						       vcard.label);
			for (i = 0; i < vcard.num_tels; i++) {
				if (vcard.tels[i].telnum)
					g_string_append_printf(s, "%s:\t\t\t%s\n",
							       _("Phone"),
							       vcard.tels[i].telnum);
			}
			for (i = 0; i < vcard.num_emails; i++) {
				if (vcard.emails[i].address)
					g_string_append_printf(s, "%s:\t\t%s\n",
							       _("Email"),
							       vcard.emails[i].address);
			}
			if (vcard.note)
				g_string_append_printf(s, "\n%s:\t\t%s\n",
						       _("Note"),
						       vcard.note);
			break;
		}
	}

	buf = g_string_free(s, FALSE);
	purple_notify_info(NULL, _("User Information"), _("User Information"),
			 buf);
	g_free(buf);
}
#endif

/* Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application.

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occurred.
   In this case arguments are not sent to the application. The `status' is
   the command reply status server returned. The `command' is the command
   reply being processed. The function has variable argument list and each
   command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

static void
silc_command_reply(SilcClient client, SilcClientConnection conn,
		   SilcCommandPayload cmd_payload, bool success,
		   SilcCommand command, SilcStatus status, ...)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	PurpleConversation *convo;
	va_list vp;

	va_start(vp, status);

	switch (command) {
	case SILC_COMMAND_JOIN:
		{
			SilcChannelEntry channel_entry;

			if (!success) {
				purple_notify_error(gc, _("Join Chat"), _("Cannot join channel"),
						  silc_get_status_message(status));
				return;
			}

			(void)va_arg(vp, char *);
			channel_entry = va_arg(vp, SilcChannelEntry);

			/* Resolve users on channel */
			silc_client_get_clients_by_channel(client, conn, channel_entry,
							   silcpurple_chat_join_done,
							   channel_entry);
		}
		break;

	case SILC_COMMAND_LEAVE:
		break;

	case SILC_COMMAND_USERS:
		break;

	case SILC_COMMAND_WHOIS:
		{
			SilcUInt32 idle, mode;
			SilcBuffer channels, user_modes;
			SilcClientEntry client_entry;
			char tmp[1024], *tmp2;
			char *moodstr, *statusstr, *contactstr, *langstr, *devicestr, *tzstr, *geostr;
			PurpleNotifyUserInfo *user_info;

			if (!success) {
				purple_notify_error(gc, _("User Information"),
						_("Cannot get user information"),
						silc_get_status_message(status));
				break;
			}

			client_entry = va_arg(vp, SilcClientEntry);
			if (!client_entry->nickname)
				break;
			(void)va_arg(vp, char *);
			(void)va_arg(vp, char *);
			(void)va_arg(vp, char *);
			channels = va_arg(vp, SilcBuffer);
			mode = va_arg(vp, SilcUInt32);
			idle = va_arg(vp, SilcUInt32);
			(void)va_arg(vp, unsigned char *);
			user_modes = va_arg(vp, SilcBuffer);

			user_info = purple_notify_user_info_new();
			tmp2 = g_markup_escape_text(client_entry->nickname, -1);
			purple_notify_user_info_add_pair(user_info, _("Nickname"), tmp2);
			g_free(tmp2);
			if (client_entry->realname) {
				tmp2 = g_markup_escape_text(client_entry->realname, -1);
				purple_notify_user_info_add_pair(user_info, _("Real Name"), tmp2);
				g_free(tmp2);
			}
			if (client_entry->username) {
				tmp2 = g_markup_escape_text(client_entry->username, -1);
				if (client_entry->hostname) {
					gchar *tmp3;
					tmp3 = g_strdup_printf("%s@%s", tmp2, client_entry->hostname);
					purple_notify_user_info_add_pair(user_info, _("Username"), tmp3);
					g_free(tmp3);
				} else
					purple_notify_user_info_add_pair(user_info, _("Username"), tmp2);
				g_free(tmp2);
			}

			if (client_entry->mode) {
				memset(tmp, 0, sizeof(tmp));
				silcpurple_get_umode_string(client_entry->mode,
						tmp, sizeof(tmp) - strlen(tmp));
				purple_notify_user_info_add_pair(user_info, _("User Modes"), tmp);
			}

			silcpurple_parse_attrs(client_entry->attrs, &moodstr, &statusstr, &contactstr, &langstr, &devicestr, &tzstr, &geostr);
			if (moodstr) {
				purple_notify_user_info_add_pair(user_info, _("Mood"), moodstr);
				g_free(moodstr);
			}

			if (statusstr) {
				tmp2 = g_markup_escape_text(statusstr, -1);
				purple_notify_user_info_add_pair(user_info, _("Status Text"), tmp2);
				g_free(statusstr);
				g_free(tmp2);
			}

			if (contactstr) {
				purple_notify_user_info_add_pair(user_info, _("Preferred Contact"), contactstr);
				g_free(contactstr);
			}

			if (langstr) {
				purple_notify_user_info_add_pair(user_info, _("Preferred Language"), langstr);
				g_free(langstr);
			}

			if (devicestr) {
				purple_notify_user_info_add_pair(user_info, _("Device"), devicestr);
				g_free(devicestr);
			}

			if (tzstr) {
				purple_notify_user_info_add_pair(user_info, _("Timezone"), tzstr);
				g_free(tzstr);
			}

			if (geostr) {
				purple_notify_user_info_add_pair(user_info, _("Geolocation"), geostr);
				g_free(geostr);
			}

			if (client_entry->server)
				purple_notify_user_info_add_pair(user_info, _("Server"), client_entry->server);

			if (channels && user_modes) {
				SilcUInt32 *umodes;
				SilcDList list =
					silc_channel_payload_parse_list(channels->data,
							channels->len);
				if (list && silc_get_mode_list(user_modes,
							silc_dlist_count(list),
							&umodes)) {
					SilcChannelPayload entry;
					int i = 0;

					memset(tmp, 0, sizeof(tmp));
					silc_dlist_start(list);
					while ((entry = silc_dlist_get(list))
							!= SILC_LIST_END) {
						SilcUInt32 name_len;
						char *m = silc_client_chumode_char(umodes[i++]);
						char *name = (char *)silc_channel_get_name(entry, &name_len);
						if (m)
							silc_strncat(tmp, sizeof(tmp) - 1, m, strlen(m));
						silc_strncat(tmp, sizeof(tmp) - 1, name, name_len);
						silc_strncat(tmp, sizeof(tmp) - 1, "  ", 1);
						silc_free(m);

					}
					tmp2 = g_markup_escape_text(tmp, -1);
					purple_notify_user_info_add_pair(user_info, _("Currently on"), tmp2);
					g_free(tmp2);
					silc_free(umodes);
				}
			}

			if (client_entry->public_key) {
				char *fingerprint, *babbleprint;
				unsigned char *pk;
				SilcUInt32 pk_len;
				pk = silc_pkcs_public_key_encode(client_entry->public_key, &pk_len);
				fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
				babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);
				purple_notify_user_info_add_pair(user_info, _("Public Key Fingerprint"), fingerprint);
				purple_notify_user_info_add_pair(user_info, _("Public Key Babbleprint"), babbleprint);
				silc_free(fingerprint);
				silc_free(babbleprint);
				silc_free(pk);
			}

#if 0 /* XXX for now, let's not show attrs here */
			if (client_entry->attrs)
				purple_request_action(gc, _("User Information"),
						_("User Information"),
						buf, 1, client_entry, 2,
						_("OK"), G_CALLBACK(silcpurple_whois_more),
						_("_More..."), G_CALLBACK(silcpurple_whois_more), gc->account, NULL, NULL);
			else
#endif
			purple_notify_userinfo(gc, client_entry->nickname, user_info, NULL, NULL);
			purple_notify_user_info_destroy(user_info);
		}
		break;

	case SILC_COMMAND_WHOWAS:
		{
			SilcClientEntry client_entry;
			char *nickname, *realname, *username, *tmp;
			PurpleNotifyUserInfo *user_info;

			if (!success) {
				purple_notify_error(gc, _("User Information"),
						  _("Cannot get user information"),
						  silc_get_status_message(status));
				break;
			}

			client_entry = va_arg(vp, SilcClientEntry);
			nickname = va_arg(vp, char *);
			username = va_arg(vp, char *);
			realname = va_arg(vp, char *);
			if (!nickname)
				break;

			user_info = purple_notify_user_info_new();
			tmp = g_markup_escape_text(nickname, -1);
			purple_notify_user_info_add_pair(user_info, _("Nickname"), tmp);
			g_free(tmp);
			if (realname) {
				tmp = g_markup_escape_text(realname, -1);
				purple_notify_user_info_add_pair(user_info, _("Real Name"), tmp);
				g_free(tmp);
			}
			if (username) {
				tmp = g_markup_escape_text(username, -1);
				if (client_entry && client_entry->hostname) {
					gchar *tmp3;
					tmp3 = g_strdup_printf("%s@%s", tmp, client_entry->hostname);
					purple_notify_user_info_add_pair(user_info, _("Username"), tmp3);
					g_free(tmp3);
				} else
					purple_notify_user_info_add_pair(user_info, _("Username"), tmp);
				g_free(tmp);
			}
			if (client_entry && client_entry->server)
				purple_notify_user_info_add_pair(user_info, _("Server"), client_entry->server);


			if (client_entry && client_entry->public_key) {
				char *fingerprint, *babbleprint;
				unsigned char *pk;
				SilcUInt32 pk_len;
				pk = silc_pkcs_public_key_encode(client_entry->public_key, &pk_len);
				fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
				babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);
				purple_notify_user_info_add_pair(user_info, _("Public Key Fingerprint"), fingerprint);
				purple_notify_user_info_add_pair(user_info, _("Public Key Babbleprint"), babbleprint);
				silc_free(fingerprint);
				silc_free(babbleprint);
				silc_free(pk);
			}

			purple_notify_userinfo(gc, nickname, user_info, NULL, NULL);
			purple_notify_user_info_destroy(user_info);
		}
		break;

	case SILC_COMMAND_DETACH:
		if (!success) {
			purple_notify_error(gc, _("Detach From Server"), _("Cannot detach"),
					  silc_get_status_message(status));
			return;
		}
		break;

	case SILC_COMMAND_TOPIC:
		{
			SilcChannelEntry channel;

			if (!success) {
				purple_notify_error(gc, _("Topic"), _("Cannot set topic"),
						  silc_get_status_message(status));
				return;
			}

			channel = va_arg(vp, SilcChannelEntry);

			convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									channel->channel_name, sg->account);
			if (!convo) {
				purple_debug_error("silc", "Got a topic for %s, which doesn't exist\n",
								 channel->channel_name);
				break;
			}

			/* Set topic */
			if (channel->topic)
				purple_conv_chat_set_topic(PURPLE_CONV_CHAT(convo), NULL, channel->topic);
		}
		break;

	case SILC_COMMAND_NICK:
		{
			/* I don't think we should need to do this because the server should
			 * be sending a SILC_NOTIFY_TYPE_NICK_CHANGE when we change our own
			 * nick, but it isn't, so we deal with it here instead. Stu. */
			SilcClientEntry local_entry;
			SilcHashTableList htl;
			SilcChannelUser chu;
			const char *oldnick;

			if (!success) {
				purple_notify_error(gc, _("Nick"), _("Failed to change nickname"),
						silc_get_status_message(status));
				return;
			}

			local_entry = va_arg(vp, SilcClientEntry);

			/* Change nick on all channels */
			silc_hash_table_list(local_entry->channels, &htl);
			while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
				convo = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
									chu->channel->channel_name, sg->account);
				if (!convo)
					continue;
				oldnick = purple_conv_chat_get_nick(PURPLE_CONV_CHAT(convo));
				if (strcmp(oldnick, purple_normalize(purple_conversation_get_account(convo), local_entry->nickname))) {
					purple_conv_chat_rename_user(PURPLE_CONV_CHAT(convo),
							oldnick, local_entry->nickname);
					purple_conv_chat_set_nick(PURPLE_CONV_CHAT(convo), local_entry->nickname);
				}
			}
			silc_hash_table_list_reset(&htl);

			purple_connection_set_display_name(gc, local_entry->nickname);
		}
		break;

	case SILC_COMMAND_LIST:
		{
			char *topic, *name;
			int usercount;
			PurpleRoomlistRoom *room;

			if (sg->roomlist_cancelled)
				break;

			if (!success) {
				purple_notify_error(gc, _("Error"), _("Error retrieving room list"),
						  silc_get_status_message(status));
				purple_roomlist_set_in_progress(sg->roomlist, FALSE);
				purple_roomlist_unref(sg->roomlist);
				sg->roomlist = NULL;
				return;
			}

			(void)va_arg(vp, SilcChannelEntry);
			name = va_arg(vp, char *);
			if (!name) {
				purple_notify_error(gc, _("Roomlist"), _("Cannot get room list"),
						  silc_get_status_message(status));
				purple_roomlist_set_in_progress(sg->roomlist, FALSE);
				purple_roomlist_unref(sg->roomlist);
				sg->roomlist = NULL;
				return;
			}
			topic = va_arg(vp, char *);
			usercount = va_arg(vp, int);

			room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, name, NULL);
			purple_roomlist_room_add_field(sg->roomlist, room, name);
			purple_roomlist_room_add_field(sg->roomlist, room,
						     SILC_32_TO_PTR(usercount));
			purple_roomlist_room_add_field(sg->roomlist, room,
						     topic ? topic : "");
			purple_roomlist_room_add(sg->roomlist, room);

			if (status == SILC_STATUS_LIST_END ||
			    status == SILC_STATUS_OK) {
				purple_roomlist_set_in_progress(sg->roomlist, FALSE);
				purple_roomlist_unref(sg->roomlist);
				sg->roomlist = NULL;
			}
		}
		break;

	case SILC_COMMAND_GETKEY:
		{
			SilcPublicKey public_key;

			if (!success) {
				purple_notify_error(gc, _("Get Public Key"),
						  _("Cannot fetch the public key"),
						  silc_get_status_message(status));
				return;
			}

			(void)va_arg(vp, SilcUInt32);
			(void)va_arg(vp, void *);
			public_key = va_arg(vp, SilcPublicKey);

			if (!public_key)
				purple_notify_error(gc, _("Get Public Key"),
						  _("Cannot fetch the public key"),
						  _("No public key was received"));
		}
		break;

	case SILC_COMMAND_INFO:
		{

			char *server_name;
			char *server_info;
			char tmp[256];

			if (!success) {
				purple_notify_error(gc, _("Server Information"),
						  _("Cannot get server information"),
						  silc_get_status_message(status));
				return;
			}

			(void)va_arg(vp, SilcServerEntry);
			server_name = va_arg(vp, char *);
			server_info = va_arg(vp, char *);

			if (server_name && server_info) {
				g_snprintf(tmp, sizeof(tmp), "Server: %s\n%s",
					   server_name, server_info);
				purple_notify_info(gc, NULL, _("Server Information"), tmp);
			}
		}
		break;

	case SILC_COMMAND_STATS:
		{
			SilcUInt32 starttime, uptime, my_clients, my_channels, my_server_ops,
			my_router_ops, cell_clients, cell_channels, cell_servers,
			clients, channels, servers, routers, server_ops, router_ops;
			SilcUInt32 buffer_length;
			SilcBufferStruct buf;

			unsigned char *server_stats;
			char *msg;

			if (!success) {
				purple_notify_error(gc, _("Server Statistics"),
						_("Cannot get server statistics"),
						silc_get_status_message(status));
				return;
			}

			server_stats = va_arg(vp, unsigned char *);
			buffer_length = va_arg(vp, SilcUInt32);
			if (!server_stats || !buffer_length) {
				purple_notify_error(gc, _("Server Statistics"),
						_("No server statistics available"), NULL);
				break;
			}
			silc_buffer_set(&buf, server_stats, buffer_length);
			silc_buffer_unformat(&buf,
					SILC_STR_UI_INT(&starttime),
					SILC_STR_UI_INT(&uptime),
					SILC_STR_UI_INT(&my_clients),
					SILC_STR_UI_INT(&my_channels),
					SILC_STR_UI_INT(&my_server_ops),
					SILC_STR_UI_INT(&my_router_ops),
					SILC_STR_UI_INT(&cell_clients),
					SILC_STR_UI_INT(&cell_channels),
					SILC_STR_UI_INT(&cell_servers),
					SILC_STR_UI_INT(&clients),
					SILC_STR_UI_INT(&channels),
					SILC_STR_UI_INT(&servers),
					SILC_STR_UI_INT(&routers),
					SILC_STR_UI_INT(&server_ops),
					SILC_STR_UI_INT(&router_ops),
					SILC_STR_END);

			msg = g_strdup_printf(_("Local server start time: %s\n"
					"Local server uptime: %s\n"
					"Local server clients: %d\n"
					"Local server channels: %d\n"
					"Local server operators: %d\n"
					"Local router operators: %d\n"
					"Local cell clients: %d\n"
					"Local cell channels: %d\n"
					"Local cell servers: %d\n"
					"Total clients: %d\n"
					"Total channels: %d\n"
					"Total servers: %d\n"
					"Total routers: %d\n"
					"Total server operators: %d\n"
					"Total router operators: %d\n"),
					silc_get_time(starttime),
					purple_str_seconds_to_string((int)uptime),
					(int)my_clients, (int)my_channels, (int)my_server_ops, (int)my_router_ops,
					(int)cell_clients, (int)cell_channels, (int)cell_servers,
					(int)clients, (int)channels, (int)servers, (int)routers,
					(int)server_ops, (int)router_ops);

			purple_notify_info(gc, NULL,
					_("Network Statistics"), msg);
			g_free(msg);
		}
		break;

	case SILC_COMMAND_PING:
		{
			if (!success) {
				purple_notify_error(gc, _("Ping"), _("Ping failed"),
								  silc_get_status_message(status));
				return;
			}

			purple_notify_info(gc, _("Ping"), _("Ping reply received from server"),
							 NULL);
		}
		break;

	case SILC_COMMAND_KILL:
		if (!success) {
			purple_notify_error(gc, _("Kill User"),
					  _("Could not kill user"),
					  silc_get_status_message(status));
			return;
		}
		break;

	case SILC_COMMAND_CMODE:
		{
			SilcChannelEntry channel_entry;
			SilcBuffer channel_pubkeys;

			if (!success)
				return;

			channel_entry = va_arg(vp, SilcChannelEntry);
			(void)va_arg(vp, SilcUInt32);
			(void)va_arg(vp, SilcPublicKey);
			channel_pubkeys = va_arg(vp, SilcBuffer);

			if (sg->chpk)
				silcpurple_chat_chauth_show(sg, channel_entry, channel_pubkeys);
		}
		break;

	default:
		if (success)
			purple_debug_info("silc", "Unhandled command: %d (succeeded)\n", command);
		else
			purple_debug_info("silc", "Unhandled command: %d (failed: %s)\n", command,
							silc_get_status_message(status));
		break;
	}

	va_end(vp);
}


/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection object which it should save somewhere.
   If the `success' is FALSE the application must always call the function
   silc_client_close_connection. */

static void
silc_connected(SilcClient client, SilcClientConnection conn,
	       SilcClientConnectionStatus status)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg;

	if (gc == NULL) {
		silc_client_close_connection(client, conn);
		return;
	}
	sg = gc->proto_data;

	switch (status) {
	case SILC_CLIENT_CONN_SUCCESS:
	case SILC_CLIENT_CONN_SUCCESS_RESUME:
		purple_connection_set_state(gc, PURPLE_CONNECTED);

		/* Send the server our buddy list */
		silcpurple_send_buddylist(gc);

		g_unlink(silcpurple_session_file(purple_account_get_username(sg->account)));

		/* Send any UMODEs configured for account */
		if (purple_account_get_bool(sg->account, "block-ims", FALSE)) {
			silc_client_command_call(sg->client, sg->conn, NULL,
					"UMODE", "+P", NULL);
		}

		return;
		break;
	case SILC_CLIENT_CONN_ERROR:
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Error during connecting to SILC Server"));
		g_unlink(silcpurple_session_file(purple_account_get_username(sg->account)));
		break;

	case SILC_CLIENT_CONN_ERROR_KE:
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR,
			_("Key Exchange failed"));
		break;

	case SILC_CLIENT_CONN_ERROR_AUTH:
		purple_connection_error_reason(gc,
			PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
			_("Authentication failed"));
		break;

	case SILC_CLIENT_CONN_ERROR_RESUME:
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_OTHER_ERROR,
			_("Resuming detached session failed. "
			  "Press Reconnect to create new connection."));
		g_unlink(silcpurple_session_file(purple_account_get_username(sg->account)));
		break;

	case SILC_CLIENT_CONN_ERROR_TIMEOUT:
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Connection timed out"));
		break;
	}

	/* Error */
	sg->conn = NULL;
	silc_client_close_connection(client, conn);
}


/* Called to indicate that connection was disconnected to the server.
   The `status' may tell the reason of the disconnection, and if the
   `message' is non-NULL it may include the disconnection message
   received from server. */

static void
silc_disconnected(SilcClient client, SilcClientConnection conn,
		  SilcStatus status, const char *message)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;

	if (sg->resuming && !sg->detaching)
		g_unlink(silcpurple_session_file(purple_account_get_username(sg->account)));

	sg->conn = NULL;

	/* Close the connection */
	if (!sg->detaching)
		purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
			_("Disconnected by server"));
	else
		/* TODO: Does this work correctly? Maybe we need to set wants_to_die? */
		purple_account_disconnect(purple_connection_get_account(gc));
}


typedef struct {
	SilcGetAuthMeth completion;
	void *context;
} *SilcPurpleGetAuthMethod;

/* Callback called when we've received the authentication method information
   from the server after we've requested it. */

static void silc_get_auth_method_callback(SilcClient client,
					  SilcClientConnection conn,
					  SilcAuthMethod auth_meth,
					  void *context)
{
	SilcPurpleGetAuthMethod internal = context;

	switch (auth_meth) {
	case SILC_AUTH_NONE:
		/* No authentication required. */
		(*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
		break;

	case SILC_AUTH_PASSWORD:
		/* By returning NULL here the library will ask the passphrase from us
		   by calling the silc_ask_passphrase. */
		(*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
		break;

	case SILC_AUTH_PUBLIC_KEY:
		/* Do not get the authentication data now, the library will generate
		   it using our default key, if we do not provide it here. */
		(*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
		break;
	}

	silc_free(internal);
}

/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. When the authentication
   method has been resolved the `completion' callback with the found
   authentication method and authentication data is called. The `conn'
   may be NULL. */

static void
silc_get_auth_method(SilcClient client, SilcClientConnection conn,
		     char *hostname, SilcUInt16 port,
		     SilcGetAuthMeth completion, void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	SilcPurpleGetAuthMethod internal;
	const char *password;

	/* Progress */
	if (sg->resuming)
		purple_connection_update_progress(gc, _("Resuming session"), 4, 5);
	else
		purple_connection_update_progress(gc, _("Authenticating connection"), 4, 5);

	/* Check configuration if we have this connection configured.  If we
	   have then return that data immediately, as it's faster way. */
	if (purple_account_get_bool(sg->account, "pubkey-auth", FALSE)) {
		completion(TRUE, SILC_AUTH_PUBLIC_KEY, NULL, 0, context);
		return;
	}
	password = purple_connection_get_password(gc);
	if (password && *password) {
		completion(TRUE, SILC_AUTH_PASSWORD, (unsigned char *)password, strlen(password), context);
		return;
	}

	/* Resolve the authentication method from server, as we may not know it. */
	internal = silc_calloc(1, sizeof(*internal));
	if (!internal)
		return;
	internal->completion = completion;
	internal->context = context;
	silc_client_request_authentication_method(client, conn,
						  silc_get_auth_method_callback,
						  internal);
}


/* Verifies received public key. The `conn_type' indicates which entity
   (server, client etc.) has sent the public key. If user decides to trust
   the application may save the key as trusted public key for later
   use. The `completion' must be called after the public key has been
   verified. */

static void
silc_verify_public_key(SilcClient client, SilcClientConnection conn,
		       SilcSocketType conn_type, unsigned char *pk,
		       SilcUInt32 pk_len, SilcSKEPKType pk_type,
		       SilcVerifyPublicKey completion, void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;

	if (!sg->conn && (conn_type == SILC_SOCKET_TYPE_SERVER ||
			  conn_type == SILC_SOCKET_TYPE_ROUTER)) {
		/* Progress */
		if (sg->resuming)
			purple_connection_update_progress(gc, _("Resuming session"), 3, 5);
		else
			purple_connection_update_progress(gc, _("Verifying server public key"),
							3, 5);
	}

	/* Verify public key */
	silcpurple_verify_public_key(client, conn, NULL, conn_type, pk,
				   pk_len, pk_type, completion, context);
}

typedef struct {
	SilcAskPassphrase completion;
	void *context;
} *SilcPurpleAskPassphrase;

static void
silc_ask_passphrase_cb(SilcPurpleAskPassphrase internal, const char *passphrase)
{
	if (!passphrase || !(*passphrase))
		internal->completion(NULL, 0, internal->context);
	else
		internal->completion((unsigned char *)passphrase,
				     strlen(passphrase), internal->context);
	silc_free(internal);
}

/* Ask (interact, that is) a passphrase from user. The passphrase is
   returned to the library by calling the `completion' callback with
   the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
   if not then the library will attempt to encode. */

static void
silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
		    SilcAskPassphrase completion, void *context)
{
	PurpleConnection *gc = client->application;
	SilcPurpleAskPassphrase internal = silc_calloc(1, sizeof(*internal));

	if (!internal)
		return;
	internal->completion = completion;
	internal->context = context;
	purple_request_input(gc, _("Passphrase"), NULL,
			   _("Passphrase required"), NULL, FALSE, TRUE, NULL,
			   _("OK"), G_CALLBACK(silc_ask_passphrase_cb),
			   _("Cancel"), G_CALLBACK(silc_ask_passphrase_cb),
			   purple_connection_get_account(gc), NULL, NULL, internal);
}


/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and
   application must explicitly cast it to correct type.  Usually `failure'
   is 32 bit failure type (see protocol specs for all protocol failure
   types). */

static void
silc_failure(SilcClient client, SilcClientConnection conn,
	     SilcProtocol protocol, void *failure)
{
	PurpleConnection *gc = client->application;
	char buf[128];

	memset(buf, 0, sizeof(buf));

	if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE) {
		SilcSKEStatus status = (SilcSKEStatus)SILC_PTR_TO_32(failure);

		if (status == SILC_SKE_STATUS_BAD_VERSION)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Version mismatch, upgrade your client"));
		if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not trust/support your public key"));
		if (status == SILC_SKE_STATUS_UNKNOWN_GROUP)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not support proposed KE group"));
		if (status == SILC_SKE_STATUS_UNKNOWN_CIPHER)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not support proposed cipher"));
		if (status == SILC_SKE_STATUS_UNKNOWN_PKCS)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not support proposed PKCS"));
		if (status == SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not support proposed hash function"));
		if (status == SILC_SKE_STATUS_UNKNOWN_HMAC)
			g_snprintf(buf, sizeof(buf),
				   _("Failure: Remote does not support proposed HMAC"));
		if (status == SILC_SKE_STATUS_INCORRECT_SIGNATURE)
			g_snprintf(buf, sizeof(buf), _("Failure: Incorrect signature"));
		if (status == SILC_SKE_STATUS_INVALID_COOKIE)
			g_snprintf(buf, sizeof(buf), _("Failure: Invalid cookie"));

		/* Show the error on the progress bar.  A more generic error message
		   is going to be showed to user after this in the silc_connected. */
		purple_connection_update_progress(gc, buf, 2, 5);
	}

	if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_CONNECTION_AUTH) {
		SilcUInt32 err = SILC_PTR_TO_32(failure);

		if (err == SILC_AUTH_FAILED)
			g_snprintf(buf, sizeof(buf), _("Failure: Authentication failed"));

		/* Show the error on the progress bar.  A more generic error message
		   is going to be showed to user after this in the silc_connected. */
		purple_connection_update_progress(gc, buf, 4, 5);
	}
}

/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). If TRUE is returned also the
   `completion' and `context' arguments must be set by the application. */

static bool
silc_key_agreement(SilcClient client, SilcClientConnection conn,
		   SilcClientEntry client_entry, const char *hostname,
		   SilcUInt16 port, SilcKeyAgreementCallback *completion,
		   void **context)
{
	silcpurple_buddy_keyagr_request(client, conn, client_entry, hostname, port);
	*completion = NULL;
	*context = NULL;
	return FALSE;
}


/* Notifies application that file transfer protocol session is being
   requested by the remote client indicated by the `client_entry' from
   the `hostname' and `port'. The `session_id' is the file transfer
   session and it can be used to either accept or reject the file
   transfer request, by calling the silc_client_file_receive or
   silc_client_file_close, respectively. */

static void
silc_ftp(SilcClient client, SilcClientConnection conn,
	 SilcClientEntry client_entry, SilcUInt32 session_id,
	 const char *hostname, SilcUInt16 port)
{
	silcpurple_ftp_request(client, conn, client_entry, session_id,
			     hostname, port);
}


/* Delivers SILC session detachment data indicated by `detach_data' to the
   application.  If application has issued SILC_COMMAND_DETACH command
   the client session in the SILC network is not quit.  The client remains
   in the network but is detached.  The detachment data may be used later
   to resume the session in the SILC Network.  The appliation is
   responsible of saving the `detach_data', to for example in a file.

   The detachment data can be given as argument to the functions
   silc_client_connect_to_server, or silc_client_add_connection when
   creating connection to remote server, inside SilcClientConnectionParams
   structure.  If it is provided the client library will attempt to resume
   the session in the network.  After the connection is created
   successfully, the application is responsible of setting the user
   interface for user into the same state it was before detaching (showing
   same channels, channel modes, etc).  It can do this by fetching the
   information (like joined channels) from the client library. */

static void
silc_detach(SilcClient client, SilcClientConnection conn,
	    const unsigned char *detach_data, SilcUInt32 detach_data_len)
{
	PurpleConnection *gc = client->application;
	SilcPurple sg = gc->proto_data;
	const char *file;

	/* Save the detachment data to file. */
	file = silcpurple_session_file(purple_account_get_username(sg->account));
	g_unlink(file);
	silc_file_writefile(file, (char *)detach_data, detach_data_len);
}

SilcClientOperations ops = {
	silc_say,
	silc_channel_message,
	silc_private_message,
	silc_notify,
	silc_command,
	silc_command_reply,
	silc_connected,
	silc_disconnected,
	silc_get_auth_method,
	silc_verify_public_key,
	silc_ask_passphrase,
	silc_failure,
	silc_key_agreement,
	silc_ftp,
	silc_detach
};
