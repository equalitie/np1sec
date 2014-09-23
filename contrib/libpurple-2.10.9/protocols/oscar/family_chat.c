/*
 * Purple's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
*/

/*
 * Family 0x000e - Routines for the Chat service.
 *
 */

#include "oscar.h"

#include <string.h>

/* Stored in the ->internal of chat connections */
struct chatconnpriv
{
	guint16 exchange;
	char *name;
	guint16 instance;
};

void
flap_connection_destroy_chat(OscarData *od, FlapConnection *conn)
{
	struct chatconnpriv *ccp = (struct chatconnpriv *)conn->internal;

	if (ccp)
		g_free(ccp->name);
	g_free(ccp);

	return;
}

int
aim_chat_readroominfo(ByteStream *bs, struct aim_chat_roominfo *outinfo)
{
	if (!bs || !outinfo)
		return 0;

	outinfo->exchange = byte_stream_get16(bs);
	outinfo->namelen = byte_stream_get8(bs);
	outinfo->name = (char *)byte_stream_getraw(bs, outinfo->namelen);
	outinfo->instance = byte_stream_get16(bs);

	return 0;
}

/*
 * Subtype 0x0002 - General room information.  Lots of stuff.
 *
 * Values I know are in here but I haven't attached
 * them to any of the 'Unknown's:
 *	- Language (English)
 *
 */
static int
infoupdate(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	int ret = 0;
	guint8 detaillevel = 0;
	struct aim_chat_roominfo roominfo;
	GSList *tlvlist;
	guint16 maxmsglen, maxvisiblemsglen;

	aim_chat_readroominfo(bs, &roominfo);

	detaillevel = byte_stream_get8(bs);

	if (detaillevel != 0x02) {
		purple_debug_misc("oscar", "faim: chat_roomupdateinfo: detail level %d not supported\n", detaillevel);
		return 1;
	}

	byte_stream_get16(bs); /* skip the TLV count */

	/*
	 * Everything else are TLVs.
	 */
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * Type 0x00d1: Maximum Message Length
	 */
	maxmsglen = aim_tlv_get16(tlvlist, 0x00d1, 1);

	/*
	 * Type 0x00da: Maximum visible message length
	 */
	maxvisiblemsglen = aim_tlv_get16(tlvlist, 0x00da, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype))) {
		ret = userfunc(od, conn, frame, maxmsglen, maxvisiblemsglen);
	}

	g_free(roominfo.name);

	aim_tlvlist_free(tlvlist);

	return ret;
}

/* Subtypes 0x0003 and 0x0004 */
static int
userlistchange(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_userinfo_t *userinfo = NULL;
	aim_rxcallback_t userfunc;
	int curcount = 0, ret = 0;

	while (byte_stream_bytes_left(bs)) {
		curcount++;
		userinfo = g_realloc(userinfo, curcount * sizeof(aim_userinfo_t));
		aim_info_extract(od, bs, &userinfo[curcount-1]);
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, curcount, userinfo);

	aim_info_free(userinfo);
	g_free(userinfo);

	return ret;
}

/*
 * Subtype 0x0005 - Send a Chat Message.
 *
 * Possible flags:
 *   AIM_CHATFLAGS_NOREFLECT   --  Unset the flag that requests messages
 *                                 should be sent to their sender.
 *   AIM_CHATFLAGS_AWAY        --  Mark the message as an autoresponse
 *                                 (Note that WinAIM does not honor this,
 *                                 and displays the message as normal.)
 *
 * XXX convert this to use tlvchains
 */
int
aim_chat_send_im(OscarData *od, FlapConnection *conn, guint16 flags, const gchar *msg, int msglen, const char *encoding, const char *language)
{
	int i;
	ByteStream bs;
	IcbmCookie *cookie;
	aim_snacid_t snacid;
	guint8 ckstr[8];
	GSList *tlvlist = NULL, *inner_tlvlist = NULL;

	if (!od || !conn || !msg || (msglen <= 0))
		return 0;

	byte_stream_new(&bs, 1142);

	snacid = aim_cachesnac(od, SNAC_FAMILY_CHAT, 0x0005, 0x0000, NULL, 0);

	/*
	 * Cookie
	 *
	 * XXX mkcookie should generate the cookie and cache it in one
	 * operation to preserve uniqueness.
	 */
	for (i = 0; i < 8; i++)
		ckstr[i] = (guint8)rand();

	cookie = aim_mkcookie(ckstr, AIM_COOKIETYPE_CHAT, NULL);
	cookie->data = NULL; /* XXX store something useful here */

	aim_cachecookie(od, cookie);

	/* ICBM Header */
	byte_stream_putraw(&bs, ckstr, 8); /* Cookie */
	byte_stream_put16(&bs, 0x0003); /* Channel */

	/*
	 * Type 1: Flag meaning this message is destined to the room.
	 */
	aim_tlvlist_add_noval(&tlvlist, 0x0001);

	/*
	 * Type 6: Reflect
	 */
	if (!(flags & AIM_CHATFLAGS_NOREFLECT))
		aim_tlvlist_add_noval(&tlvlist, 0x0006);

	/*
	 * Type 7: Autoresponse
	 */
	if (flags & AIM_CHATFLAGS_AWAY)
		aim_tlvlist_add_noval(&tlvlist, 0x0007);

	/*
	 * SubTLV: Type 1: Message
	 */
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0001, msglen, (guchar *)msg);

	/*
	 * SubTLV: Type 2: Encoding
	 */
	if (encoding != NULL)
		aim_tlvlist_add_str(&inner_tlvlist, 0x0002, encoding);

	/*
	 * SubTLV: Type 3: Language
	 */
	if (language != NULL)
		aim_tlvlist_add_str(&inner_tlvlist, 0x0003, language);

	/*
	 * Type 5: Message block.  Contains more TLVs.
	 *
	 * This could include other information... We just
	 * put in a message TLV however.
	 *
	 */
	aim_tlvlist_add_frozentlvlist(&tlvlist, 0x0005, &inner_tlvlist);

	aim_tlvlist_write(&bs, &tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_CHAT, 0x0005, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x0006
 *
 * We could probably include this in the normal ICBM parsing
 * code as channel 0x0003, however, since only the start
 * would be the same, we might as well do it here.
 *
 * General outline of this SNAC:
 *   snac
 *   cookie
 *   channel id
 *   tlvlist
 *     unknown
 *     source user info
 *       name
 *       evility
 *       userinfo tlvs
 *         online time
 *         etc
 *     message metatlv
 *       message tlv
 *         message string
 *       possibly others
 *
 */
static int
incomingim_ch3(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0, i;
	aim_rxcallback_t userfunc;
	aim_userinfo_t userinfo;
	guint8 cookie[8];
	guint16 channel;
	GSList *tlvlist;
	char *msg = NULL;
	int len = 0;
	char *encoding = NULL, *language = NULL;
	IcbmCookie *ck;
	aim_tlv_t *tlv;
	ByteStream tbs;

	memset(&userinfo, 0, sizeof(aim_userinfo_t));

	/*
	 * Read ICBM Cookie.
	 */
	for (i = 0; i < 8; i++)
		cookie[i] = byte_stream_get8(bs);

	if ((ck = aim_uncachecookie(od, cookie, AIM_COOKIETYPE_CHAT))) {
		g_free(ck->data);
		g_free(ck);
	}

	/*
	 * Channel ID
	 *
	 * Channel 0x0003 is used for chat messages.
	 *
	 */
	channel = byte_stream_get16(bs);

	if (channel != 0x0003) {
		purple_debug_misc("oscar", "faim: chat_incoming: unknown channel! (0x%04x)\n", channel);
		return 0;
	}

	/*
	 * Start parsing TLVs right away.
	 */
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * Type 0x0003: Source User Information
	 */
	tlv = aim_tlv_gettlv(tlvlist, 0x0003, 1);
	if (tlv != NULL)
	{
		byte_stream_init(&tbs, tlv->value, tlv->length);
		aim_info_extract(od, &tbs, &userinfo);
	}

	/*
	 * Type 0x0005: Message Block.  Conains more TLVs.
	 */
	tlv = aim_tlv_gettlv(tlvlist, 0x0005, 1);
	if (tlv != NULL)
	{
		GSList *inner_tlvlist;
		aim_tlv_t *inner_tlv;

		byte_stream_init(&tbs, tlv->value, tlv->length);
		inner_tlvlist = aim_tlvlist_read(&tbs);

		/*
		 * Type 0x0001: Message.
		 */
		inner_tlv = aim_tlv_gettlv(inner_tlvlist, 0x0001, 1);
		if (inner_tlv != NULL)
		{
			len = inner_tlv->length;
			msg = aim_tlv_getvalue_as_string(inner_tlv);
		}

		/*
		 * Type 0x0002: Encoding.
		 */
		encoding = aim_tlv_getstr(inner_tlvlist, 0x0002, 1);

		/*
		 * Type 0x0003: Language.
		 */
		language = aim_tlv_getstr(inner_tlvlist, 0x0003, 1);

		aim_tlvlist_free(inner_tlvlist);
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, &userinfo, len, msg, encoding, language);

	aim_info_free(&userinfo);
	g_free(msg);
	g_free(encoding);
	g_free(language);
	aim_tlvlist_free(tlvlist);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0002)
		return infoupdate(od, conn, mod, frame, snac, bs);
	else if ((snac->subtype == 0x0003) || (snac->subtype == 0x0004))
		return userlistchange(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0006)
		return incomingim_ch3(od, conn, mod, frame, snac, bs);

	return 0;
}

int
chat_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_CHAT;
	mod->version = 0x0001;
	mod->toolid = 0x0010;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "chat", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
