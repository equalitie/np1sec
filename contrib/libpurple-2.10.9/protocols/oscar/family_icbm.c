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
 * Family 0x0004 - Routines for sending/receiving Instant Messages.
 *
 * Note the term ICBM (Inter-Client Basic Message) which blankets
 * all types of generically routed through-server messages.  Within
 * the ICBM types (family 4), a channel is defined.  Each channel
 * represents a different type of message.  Channel 1 is used for
 * what would commonly be called an "instant message".  Channel 2
 * is used for negotiating "rendezvous".  These transactions end in
 * something more complex happening, such as a chat invitation, or
 * a file transfer.  Channel 3 is used for chat messages (not in
 * the same family as these channels).  Channel 4 is used for
 * various ICQ messages.  Examples are normal messages, URLs, and
 * old-style authorization.
 *
 * In addition to the channel, every ICBM contains a cookie.  For
 * standard IMs, these are only used for error messages.  However,
 * the more complex rendezvous messages make suitably more complex
 * use of this field.
 *
 * TODO: Split this up into an im.c file an an icbm.c file.  It
 *       will be beautiful, you'll see.
 *
 *       Make sure flap_connection_findbygroup is used by all functions.
 */

#include "encoding.h"
#include "oscar.h"
#include "peer.h"

#ifdef _WIN32
#include "win32dep.h"
#endif

#include "util.h"

static const char * const errcodereason[] = {
	N_("Invalid error"),
	N_("Not logged in"),
	N_("Cannot receive IM due to parental controls"),
	N_("Cannot send SMS without accepting terms"),
	N_("Cannot send SMS"), /* SMS_WITHOUT_DISCLAIMER is weird */
	N_("Cannot send SMS to this country"),
	N_("Unknown error"), /* Undocumented */
	N_("Unknown error"), /* Undocumented */
	N_("Cannot send SMS to unknown country"),
	N_("Bot accounts cannot initiate IMs"),
	N_("Bot account cannot IM this user"),
	N_("Bot account reached IM limit"),
	N_("Bot account reached daily IM limit"),
	N_("Bot account reached monthly IM limit"),
	N_("Unable to receive offline messages"),
	N_("Offline message store full")
};
static const int errcodereasonlen = G_N_ELEMENTS(errcodereason);

/**
 * Add a standard ICBM header to the given bstream with the given
 * information.
 *
 * @param bs The bstream to write the ICBM header to.
 * @param c c is for cookie, and cookie is for me.
 * @param channel The ICBM channel (1 through 4).
 * @param bn Null-terminated scrizeen nizame.
 * @return The number of bytes written.  It's really not useful.
 */
static int aim_im_puticbm(ByteStream *bs, const guchar *c, guint16 channel, const char *bn)
{
	byte_stream_putraw(bs, c, 8);
	byte_stream_put16(bs, channel);
	byte_stream_put8(bs, strlen(bn));
	byte_stream_putstr(bs, bn);
	return 8+2+1+strlen(bn);
}

/**
 * Generates a random ICBM cookie in a character array of length 8
 * and copies it into the variable passed as cookie
 * TODO: Maybe we should stop limiting our characters to the visible range?
 */
void aim_icbm_makecookie(guchar *cookie)
{
	int i;

	/* Should be like "21CBF95" and null terminated */
	for (i = 0; i < 7; i++)
		cookie[i] = 0x30 + ((guchar)rand() % 10);
	cookie[7] = '\0';
}

/*
 * Subtype 0x0001 - Error
 */
static int
error(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_snac_t *snac2;
	guint16 reason, errcode = 0;
	const char *bn;
	GSList *tlvlist;
	PurpleConnection *gc = od->gc;
#ifdef TODOFT
	PurpleXfer *xfer;
#endif
	const char *reason_str;
	char *buf;

	snac2 = aim_remsnac(od, snac->id);
	if (!snac2) {
		purple_debug_misc("oscar", "icbm error: received response from unknown request!\n");
		return 1;
	}

	if (snac2->family != SNAC_FAMILY_ICBM) {
		purple_debug_misc("oscar", "icbm error: received response from invalid request! %d\n", snac2->family);
		g_free(snac2->data);
		g_free(snac2);
		return 1;
	}

	/* Data is assumed to be the destination bn */
	bn = snac2->data;
	if (!bn || bn[0] == '\0') {
		purple_debug_misc("oscar", "icbm error: received response from request without a buddy name!\n");
		g_free(snac2->data);
		g_free(snac2);
		return 1;
	}

	reason = byte_stream_get16(bs);

	tlvlist = aim_tlvlist_read(bs);
	if (aim_tlv_gettlv(tlvlist, 0x0008, 1))
		errcode = aim_tlv_get16(tlvlist, 0x0008, 1);
	aim_tlvlist_free(tlvlist);

	purple_debug_error("oscar",
			   "Message error with bn %s and reason %hu and errcode %hu\n",
				bn, reason, errcode);

#ifdef TODOFT
	/* If this was a file transfer request, bn is a cookie */
	if ((xfer = oscar_find_xfer_by_cookie(od->file_transfers, bn))) {
		purple_xfer_cancel_remote(xfer);
		return 1;
	}
#endif

	/* Notify the user that the message wasn't delivered */
	reason_str = oscar_get_msgerr_reason(reason);
	if (errcode != 0 && errcode < errcodereasonlen)
		buf = g_strdup_printf(_("Unable to send message: %s (%s)"), reason_str,
		                      _(errcodereason[errcode]));
	else
		buf = g_strdup_printf(_("Unable to send message: %s"), reason_str);

	if (!purple_conv_present_error(bn, purple_connection_get_account(gc), buf)) {
		g_free(buf);
		if (errcode != 0 && errcode < errcodereasonlen)
			buf = g_strdup_printf(_("Unable to send message to %s: %s (%s)"),
			                      bn ? bn : "(unknown)", reason_str,
			                      _(errcodereason[errcode]));
		else
			buf = g_strdup_printf(_("Unable to send message to %s: %s"),
			                      bn ? bn : "(unknown)", reason_str);
		purple_notify_error(od->gc, NULL, buf, reason_str);
	}
	g_free(buf);

	g_free(snac2->data);
	g_free(snac2);

	return 1;
}

/**
 * Subtype 0x0002 - Set ICBM parameters.
 *
 * I definitely recommend sending this.  If you don't, you'll be stuck
 * with the rather unreasonable defaults.
 *
 */
int aim_im_setparams(OscarData *od, struct aim_icbmparameters *params)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	if (!params)
		return -EINVAL;

	byte_stream_new(&bs, 16);

	/* This is read-only (see Parameter Reply). Must be set to zero here. */
	byte_stream_put16(&bs, 0x0000);

	/* These are all read-write */
	byte_stream_put32(&bs, params->flags);
	byte_stream_put16(&bs, params->maxmsglen);
	byte_stream_put16(&bs, params->maxsenderwarn);
	byte_stream_put16(&bs, params->maxrecverwarn);
	byte_stream_put32(&bs, params->minmsginterval);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0002, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0002, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/**
 * Subtype 0x0004 - Request ICBM parameter information.
 *
 */
int aim_im_reqparams(OscarData *od)
{
	FlapConnection *conn;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_ICBM, 0x0004);

	return 0;
}

/**
 * Subtype 0x0005 - Receive parameter information.
 *
 */
static int aim_im_paraminfo(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	struct aim_icbmparameters params;

	params.maxchan = byte_stream_get16(bs);
	params.flags = byte_stream_get32(bs);
	params.maxmsglen = byte_stream_get16(bs);
	params.maxsenderwarn = byte_stream_get16(bs);
	params.maxrecverwarn = byte_stream_get16(bs);
	params.minmsginterval = byte_stream_get32(bs);

	params.flags = AIM_IMPARAM_FLAG_CHANNEL_MSGS_ALLOWED
			| AIM_IMPARAM_FLAG_MISSED_CALLS_ENABLED
			| AIM_IMPARAM_FLAG_EVENTS_ALLOWED
			| AIM_IMPARAM_FLAG_SMS_SUPPORTED
			| AIM_IMPARAM_FLAG_OFFLINE_MSGS_ALLOWED
			| AIM_IMPARAM_FLAG_USE_HTML_FOR_ICQ;
	params.maxmsglen = 8000;
	params.minmsginterval = 0;

	aim_im_setparams(od, &params);

	return 0;
}

/**
 * Subtype 0x0006 - Send an ICBM (instant message).
 *
 *
 * Possible flags:
 *   AIM_IMFLAGS_AWAY  -- Marks the message as an autoresponse
 *   AIM_IMFLAGS_OFFLINE--If destination is offline, store it until they are
 *                        online (probably ICQ only).
 *
 * Implementation note:  Since this is one of the most-used functions
 * in all of libfaim, it is written with performance in mind.  As such,
 * it is not as clear as it could be in respect to how this message is
 * supposed to be layed out. Most obviously, tlvlists should be used
 * instead of writing out the bytes manually.
 */
int aim_im_sendch1_ext(OscarData *od, struct aim_sendimext_args *args)
{
	FlapConnection *conn;
	aim_snacid_t snacid;
	ByteStream data;
	guchar cookie[8];
	int msgtlvlen;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	if (!args)
		return -EINVAL;

	if (!args->msg || (args->msglen <= 0))
		return -EINVAL;

	if (args->msglen > MAXMSGLEN)
		return -E2BIG;

	/* Painfully calculate the size of the message TLV */
	msgtlvlen = 1 + 1; /* 0501 */
	msgtlvlen += 2 + args->featureslen;
	msgtlvlen += 2 /* 0101 */ + 2 /* block len */;
	msgtlvlen += 4 /* charset */ + args->msglen;

	byte_stream_new(&data, msgtlvlen + 128);

	/* Generate an ICBM cookie */
	aim_icbm_makecookie(cookie);

	/* ICBM header */
	aim_im_puticbm(&data, cookie, 0x0001, args->destbn);

	/* Message TLV (type 0x0002) */
	byte_stream_put16(&data, 0x0002);
	byte_stream_put16(&data, msgtlvlen);

	/* Features TLV (type 0x0501) */
	byte_stream_put16(&data, 0x0501);
	byte_stream_put16(&data, args->featureslen);
	byte_stream_putraw(&data, args->features, args->featureslen);

	/* Insert message text in a TLV (type 0x0101) */
	byte_stream_put16(&data, 0x0101);

	/* Message block length */
	byte_stream_put16(&data, args->msglen + 0x04);

	/* Character set */
	byte_stream_put16(&data, args->charset);
	/* Character subset -- we always use 0 here */
	byte_stream_put16(&data, 0x0);

	/* Message.  Not terminated */
	byte_stream_putraw(&data, (guchar *)args->msg, args->msglen);

	/* Set the Autoresponse flag */
	if (args->flags & AIM_IMFLAGS_AWAY) {
		byte_stream_put16(&data, 0x0004);
		byte_stream_put16(&data, 0x0000);
	} else {
		/* Set the Request Acknowledge flag */
		byte_stream_put16(&data, 0x0003);
		byte_stream_put16(&data, 0x0000);

		if (args->flags & AIM_IMFLAGS_OFFLINE) {
			/* Allow this message to be queued as an offline message */
			byte_stream_put16(&data, 0x0006);
			byte_stream_put16(&data, 0x0000);
		}
	}

	/*
	 * Set the I HAVE A REALLY PURTY ICON flag.
	 * XXX - This should really only be sent on initial
	 * IMs and when you change your icon.
	 */
	if (args->flags & AIM_IMFLAGS_HASICON) {
		byte_stream_put16(&data, 0x0008);
		byte_stream_put16(&data, 0x000c);
		byte_stream_put32(&data, args->iconlen);
		byte_stream_put16(&data, 0x0001);
		byte_stream_put16(&data, args->iconsum);
		byte_stream_put32(&data, args->iconstamp);
	}

	/*
	 * Set the Buddy Icon Requested flag.
	 * XXX - Every time?  Surely not...
	 */
	if (args->flags & AIM_IMFLAGS_BUDDYREQ) {
		byte_stream_put16(&data, 0x0009);
		byte_stream_put16(&data, 0x0000);
	}

	/* XXX - should be optional */
	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, args->destbn, strlen(args->destbn)+1);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &data);
	byte_stream_destroy(&data);

	/* clean out SNACs over 60sec old */
	aim_cleansnacs(od, 60);

	return 0;
}

/*
 * Subtype 0x0006 - Send a chat invitation.
 */
int aim_im_sendch2_chatinvite(OscarData *od, const char *bn, const char *msg, guint16 exchange, const char *roomname, guint16 instance)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	IcbmCookie *msgcookie;
	struct aim_invite_priv *priv;
	guchar cookie[8];
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	if (!bn || !msg || !roomname)
		return -EINVAL;

	aim_icbm_makecookie(cookie);

	byte_stream_new(&bs, 1142+strlen(bn)+strlen(roomname)+strlen(msg));

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, bn, strlen(bn)+1);

	/* XXX should be uncached by an unwritten 'invite accept' handler */
	priv = g_malloc(sizeof(struct aim_invite_priv));
	priv->bn = g_strdup(bn);
	priv->roomname = g_strdup(roomname);
	priv->exchange = exchange;
	priv->instance = instance;

	if ((msgcookie = aim_mkcookie(cookie, AIM_COOKIETYPE_INVITE, priv)))
		aim_cachecookie(od, msgcookie);
	else
		g_free(priv);

	/* ICBM Header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	/*
	 * TLV t(0005)
	 *
	 * Everything else is inside this TLV.
	 *
	 * Sigh.  AOL was rather inconsistent right here.  So we have
	 * to play some minor tricks.  Right inside the type 5 is some
	 * raw data, followed by a series of TLVs.
	 *
	 */
	byte_stream_new(&hdrbs, 2+8+16+6+4+4+strlen(msg)+4+2+1+strlen(roomname)+2);

	byte_stream_put16(&hdrbs, 0x0000); /* Unknown! */
	byte_stream_putraw(&hdrbs, cookie, sizeof(cookie)); /* I think... */
	byte_stream_putcaps(&hdrbs, OSCAR_CAPABILITY_CHAT);

	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, 0x0001);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);
	aim_tlvlist_add_str(&inner_tlvlist, 0x000c, msg);
	aim_tlvlist_add_chatroom(&inner_tlvlist, 0x2711, exchange, roomname, instance);
	aim_tlvlist_write(&hdrbs, &inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/**
 * Subtype 0x0006 - Send your icon to a given user.
 *
 * This is also performance sensitive. (If you can believe it...)
 *
 */
int aim_im_sendch2_icon(OscarData *od, const char *bn, const guint8 *icon, int iconlen, time_t stamp, guint16 iconsum)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	guchar cookie[8];

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	if (!bn || !icon || (iconlen <= 0) || (iconlen >= MAXICONLEN))
		return -EINVAL;

	aim_icbm_makecookie(cookie);

	byte_stream_new(&bs, 8+2+1+strlen(bn)+2+2+2+8+16+2+2+2+2+2+2+2+4+4+4+iconlen+strlen(AIM_ICONIDENT)+2+2);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	/*
	 * TLV t(0005)
	 *
	 * Encompasses everything below.
	 */
	byte_stream_put16(&bs, 0x0005);
	byte_stream_put16(&bs, 2+8+16+6+4+4+iconlen+4+4+4+strlen(AIM_ICONIDENT));

	byte_stream_put16(&bs, 0x0000);
	byte_stream_putraw(&bs, cookie, 8);
	byte_stream_putcaps(&bs, OSCAR_CAPABILITY_BUDDYICON);

	/* TLV t(000a) */
	byte_stream_put16(&bs, 0x000a);
	byte_stream_put16(&bs, 0x0002);
	byte_stream_put16(&bs, 0x0001);

	/* TLV t(000f) */
	byte_stream_put16(&bs, 0x000f);
	byte_stream_put16(&bs, 0x0000);

	/* TLV t(2711) */
	byte_stream_put16(&bs, 0x2711);
	byte_stream_put16(&bs, 4+4+4+iconlen+strlen(AIM_ICONIDENT));
	byte_stream_put16(&bs, 0x0000);
	byte_stream_put16(&bs, iconsum);
	byte_stream_put32(&bs, iconlen);
	byte_stream_put32(&bs, stamp);
	byte_stream_putraw(&bs, icon, iconlen);
	byte_stream_putstr(&bs, AIM_ICONIDENT);

	/* TLV t(0003) */
	byte_stream_put16(&bs, 0x0003);
	byte_stream_put16(&bs, 0x0000);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/**
 * Cancel a rendezvous invitation.  It could be an invitation to
 * establish a direct connection, or a file-send, or a chat invite.
 */
void
aim_im_sendch2_cancel(PeerConnection *peer_conn)
{
	OscarData *od;
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;

	od = peer_conn->od;
	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 118+strlen(peer_conn->bn));

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, peer_conn->cookie, 0x0002, peer_conn->bn);

	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003);

	byte_stream_new(&hdrbs, 64);

	byte_stream_put16(&hdrbs, AIM_RENDEZVOUS_CANCEL);
	byte_stream_putraw(&hdrbs, peer_conn->cookie, 8);
	byte_stream_putcaps(&hdrbs, peer_conn->type);

	/* This TLV means "cancel!" */
	aim_tlvlist_add_16(&inner_tlvlist, 0x000b, 0x0001);
	aim_tlvlist_write(&hdrbs, &inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0006 - Send an "I accept and I've connected to
 * you" message.
 */
void
aim_im_sendch2_connected(PeerConnection *peer_conn)
{
	OscarData *od;
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	od = peer_conn->od;
	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 11+strlen(peer_conn->bn) + 4+2+8+16);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, peer_conn->cookie, 0x0002, peer_conn->bn);

	byte_stream_put16(&bs, 0x0005);
	byte_stream_put16(&bs, 0x001a);
	byte_stream_put16(&bs, AIM_RENDEZVOUS_CONNECTED);
	byte_stream_putraw(&bs, peer_conn->cookie, 8);
	byte_stream_putcaps(&bs, peer_conn->type);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0006 - Send a direct connect rendezvous ICBM.  This
 * could have a number of meanings, depending on the content:
 * "I want you to connect to me"
 * "I want to connect to you"
 * "I want to connect through a proxy server"
 */
void
aim_im_sendch2_odc_requestdirect(OscarData *od, guchar *cookie, const char *bn, const guint8 *ip, guint16 port, guint16 requestnumber)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 246+strlen(bn));

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003);

	byte_stream_new(&hdrbs, 128);

	byte_stream_put16(&hdrbs, AIM_RENDEZVOUS_PROPOSE);
	byte_stream_putraw(&hdrbs, cookie, 8);
	byte_stream_putcaps(&hdrbs, OSCAR_CAPABILITY_DIRECTIM);

	aim_tlvlist_add_raw(&inner_tlvlist, 0x0002, 4, ip);
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0003, 4, ip);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0005, port);
	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, requestnumber);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);
	aim_tlvlist_write(&hdrbs, &inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0006 - Send a direct connect rendezvous ICBM asking the
 * remote user to connect to us via a proxy server.
 */
void
aim_im_sendch2_odc_requestproxy(OscarData *od, guchar *cookie, const char *bn, const guint8 *ip, guint16 pin, guint16 requestnumber)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;
	guint8 ip_comp[4];

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 246+strlen(bn));

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003);

	byte_stream_new(&hdrbs, 128);

	byte_stream_put16(&hdrbs, AIM_RENDEZVOUS_PROPOSE);
	byte_stream_putraw(&hdrbs, cookie, 8);
	byte_stream_putcaps(&hdrbs, OSCAR_CAPABILITY_DIRECTIM);

	aim_tlvlist_add_raw(&inner_tlvlist, 0x0002, 4, ip);
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0003, 4, ip);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0005, pin);
	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, requestnumber);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x0010);

	/* Send the bitwise complement of the port and ip.  As a check? */
	ip_comp[0] = ~ip[0];
	ip_comp[1] = ~ip[1];
	ip_comp[2] = ~ip[2];
	ip_comp[3] = ~ip[3];
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0016, 4, ip_comp);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0017, ~pin);

	aim_tlvlist_write(&hdrbs, &inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0006 - Send an "I want to send you this file" message
 *
 */
void
aim_im_sendch2_sendfile_requestdirect(OscarData *od, guchar *cookie, const char *bn, const guint8 *ip, guint16 port, guint16 requestnumber, const gchar *filename, guint32 size, guint16 numfiles)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;

	g_return_if_fail(bn != NULL);
	g_return_if_fail(ip != NULL);

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 1014);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003);

	byte_stream_new(&hdrbs, 512);

	byte_stream_put16(&hdrbs, AIM_RENDEZVOUS_PROPOSE);
	byte_stream_putraw(&hdrbs, cookie, 8);
	byte_stream_putcaps(&hdrbs, OSCAR_CAPABILITY_SENDFILE);

	aim_tlvlist_add_raw(&inner_tlvlist, 0x0002, 4, ip);
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0003, 4, ip);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0005, port);
	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, requestnumber);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);
	/* TODO: Send 0x0016 and 0x0017 */

	if (filename != NULL)
	{
		ByteStream inner_bs;

		/* Begin TLV t(2711) */
		byte_stream_new(&inner_bs, 2+2+4+strlen(filename)+1);
		byte_stream_put16(&inner_bs, (numfiles > 1) ? 0x0002 : 0x0001);
		byte_stream_put16(&inner_bs, numfiles);
		byte_stream_put32(&inner_bs, size);

		/* Filename - NULL terminated, for some odd reason */
		byte_stream_putstr(&inner_bs, filename);
		byte_stream_put8(&inner_bs, 0x00);

		aim_tlvlist_add_raw(&inner_tlvlist, 0x2711, inner_bs.len, inner_bs.data);
		byte_stream_destroy(&inner_bs);
		/* End TLV t(2711) */
	}

	aim_tlvlist_write(&hdrbs, &inner_tlvlist);
	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0006 - Send a sendfile connect rendezvous ICBM asking the
 * remote user to connect to us via a proxy server.
 */
void
aim_im_sendch2_sendfile_requestproxy(OscarData *od, guchar *cookie, const char *bn, const guint8 *ip, guint16 pin, guint16 requestnumber, const gchar *filename, guint32 size, guint16 numfiles)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream hdrbs;
	guint8 ip_comp[4];

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM);
	if (conn == NULL)
		return;

	byte_stream_new(&bs, 1014);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0006, 0x0000, NULL, 0);

	/* ICBM header */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);

	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003);

	byte_stream_new(&hdrbs, 512);

	byte_stream_put16(&hdrbs, AIM_RENDEZVOUS_PROPOSE);
	byte_stream_putraw(&hdrbs, cookie, 8);
	byte_stream_putcaps(&hdrbs, OSCAR_CAPABILITY_SENDFILE);

	aim_tlvlist_add_raw(&inner_tlvlist, 0x0002, 4, ip);
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0003, 4, ip);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0005, pin);
	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, requestnumber);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x0010);

	/* Send the bitwise complement of the port and ip.  As a check? */
	ip_comp[0] = ~ip[0];
	ip_comp[1] = ~ip[1];
	ip_comp[2] = ~ip[2];
	ip_comp[3] = ~ip[3];
	aim_tlvlist_add_raw(&inner_tlvlist, 0x0016, 4, ip_comp);
	aim_tlvlist_add_16(&inner_tlvlist, 0x0017, ~pin);

	if (filename != NULL)
	{
		ByteStream filename_bs;

		/* Begin TLV t(2711) */
		byte_stream_new(&filename_bs, 2+2+4+strlen(filename)+1);
		byte_stream_put16(&filename_bs, (numfiles > 1) ? 0x0002 : 0x0001);
		byte_stream_put16(&filename_bs, numfiles);
		byte_stream_put32(&filename_bs, size);

		/* Filename - NULL terminated, for some odd reason */
		byte_stream_putstr(&filename_bs, filename);
		byte_stream_put8(&filename_bs, 0x00);

		aim_tlvlist_add_raw(&inner_tlvlist, 0x2711, filename_bs.len, filename_bs.data);
		byte_stream_destroy(&filename_bs);
		/* End TLV t(2711) */
	}

	aim_tlvlist_write(&hdrbs, &inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&hdrbs), hdrbs.data);
	byte_stream_destroy(&hdrbs);

	aim_tlvlist_write(&bs, &outer_tlvlist);

	aim_tlvlist_free(inner_tlvlist);
	aim_tlvlist_free(outer_tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);
}

static void
incomingim_ch1_parsemsg(OscarData *od, aim_userinfo_t *userinfo, ByteStream *message, struct aim_incomingim_ch1_args *args)
{
	PurpleAccount *account = purple_connection_get_account(od->gc);
	/*
	 * We're interested in the inner TLV 0x101, which contains precious, precious message.
	 */
	while (byte_stream_bytes_left(message) >= 4) {
		guint16 type = byte_stream_get16(message);
		guint16 length = byte_stream_get16(message);
		if (type == 0x101) {
			gchar *msg;
			guint16 msglen = length - 4; /* charset + charsubset */
			guint16 charset = byte_stream_get16(message);
			byte_stream_advance(message, 2); /* charsubset */

			msg = byte_stream_getstr(message, msglen);
			args->msg = oscar_decode_im(account, userinfo->bn, charset, msg, msglen);
			g_free(msg);
		} else {
			byte_stream_advance(message, length);
		}
	}
}

static int
incomingim_ch1(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, guint16 channel, aim_userinfo_t *userinfo, ByteStream *bs, guint8 *cookie)
{
	guint16 type, length;
	aim_rxcallback_t userfunc;
	int ret = 0;
	struct aim_incomingim_ch1_args args;
	unsigned int endpos;

	memset(&args, 0, sizeof(args));

	/*
	 * This used to be done using tlvchains.  For performance reasons,
	 * I've changed it to process the TLVs in-place.  This avoids lots
	 * of per-IM memory allocations.
	 */
	while (byte_stream_bytes_left(bs) >= 4)
	{
		type = byte_stream_get16(bs);
		length = byte_stream_get16(bs);

		if (length > byte_stream_bytes_left(bs))
		{
			purple_debug_misc("oscar", "Received an IM containing an invalid message part from %s.  They are probably trying to do something malicious.\n", userinfo->bn);
			break;
		}

		endpos = byte_stream_curpos(bs) + length;

		if (type == 0x0002) { /* Message Block */
			ByteStream tlv02;
			byte_stream_init(&tlv02, bs->data + bs->offset, length);
			incomingim_ch1_parsemsg(od, userinfo, &tlv02, &args);
		} else if (type == 0x0003) { /* Server Ack Requested */
			args.icbmflags |= AIM_IMFLAGS_ACK;
		} else if (type == 0x0004) { /* Message is Auto Response */
			args.icbmflags |= AIM_IMFLAGS_AWAY;
		} else if (type == 0x0006) { /* Message was received offline. */
			/*
			 * This flag is set on incoming offline messages for both
			 * AIM and ICQ accounts.
			 */
			args.icbmflags |= AIM_IMFLAGS_OFFLINE;
		} else if (type == 0x0008) { /* I-HAVE-A-REALLY-PURTY-ICON Flag */
			args.iconlen = byte_stream_get32(bs);
			byte_stream_get16(bs); /* 0x0001 */
			args.iconsum = byte_stream_get16(bs);
			args.iconstamp = byte_stream_get32(bs);

			/*
			 * This looks to be a client bug.  MacAIM 4.3 will
			 * send this tag, but with all zero values, in the
			 * first message of a conversation. This makes no
			 * sense whatsoever, so I'm going to say its a bug.
			 *
			 * You really shouldn't advertise a zero-length icon
			 * anyway.
			 *
			 */
			if (args.iconlen)
				args.icbmflags |= AIM_IMFLAGS_HASICON;
		} else if (type == 0x0009) {
			args.icbmflags |= AIM_IMFLAGS_BUDDYREQ;
		} else if (type == 0x000b) { /* Non-direct connect typing notification */
			args.icbmflags |= AIM_IMFLAGS_TYPINGNOT;
		} else if (type == 0x0016) {
			/*
			 * UTC timestamp for when the message was sent.  Only
			 * provided for offline messages.
			 */
			args.timestamp = byte_stream_get32(bs);
		}

		/*
		 * This is here to protect ourselves from ourselves.  That
		 * is, if something above doesn't completely parse its value
		 * section, or, worse, overparses it, this will set the
		 * stream where it needs to be in order to land on the next
		 * TLV when the loop continues.
		 *
		 */
		byte_stream_setpos(bs, endpos);
	}


	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, channel, userinfo, &args);

	g_free(args.msg);
	return ret;
}

static void
incomingim_ch2_buddylist(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, aim_userinfo_t *userinfo, IcbmArgsCh2 *args, ByteStream *servdata)
{
	/*
	 * This goes like this...
	 *
	 *   group name length
	 *   group name
	 *     num of buddies in group
	 *     buddy name length
	 *     buddy name
	 *     buddy name length
	 *     buddy name
	 *     ...
	 *   group name length
	 *   group name
	 *     num of buddies in group
	 *     buddy name length
	 *     buddy name
	 *     ...
	 *   ...
	 */
	while (byte_stream_bytes_left(servdata))
	{
		guint16 gnlen, numb;
		int i;
		char *gn;

		gnlen = byte_stream_get16(servdata);
		gn = byte_stream_getstr(servdata, gnlen);
		numb = byte_stream_get16(servdata);

		for (i = 0; i < numb; i++) {
			guint16 bnlen;
			char *bn;

			bnlen = byte_stream_get16(servdata);
			bn = byte_stream_getstr(servdata, bnlen);

			purple_debug_misc("oscar", "got a buddy list from %s: group %s, buddy %s\n", userinfo->bn, gn, bn);

			g_free(bn);
		}

		g_free(gn);
	}

	return;
}

static void
incomingim_ch2_buddyicon_free(OscarData *od, IcbmArgsCh2 *args)
{
	g_free(args->info.icon.icon);

	return;
}

static void
incomingim_ch2_buddyicon(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, aim_userinfo_t *userinfo, IcbmArgsCh2 *args, ByteStream *servdata)
{
	args->info.icon.checksum = byte_stream_get32(servdata);
	args->info.icon.length = byte_stream_get32(servdata);
	args->info.icon.timestamp = byte_stream_get32(servdata);
	args->info.icon.icon = byte_stream_getraw(servdata, args->info.icon.length);

	args->destructor = (void *)incomingim_ch2_buddyicon_free;

	return;
}

static void
incomingim_ch2_chat_free(OscarData *od, IcbmArgsCh2 *args)
{
	/* XXX - aim_chat_roominfo_free() */
	g_free(args->info.chat.roominfo.name);

	return;
}

static void
incomingim_ch2_chat(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, aim_userinfo_t *userinfo, IcbmArgsCh2 *args, ByteStream *servdata)
{
	/*
	 * Chat room info.
	 */
	aim_chat_readroominfo(servdata, &args->info.chat.roominfo);

	args->destructor = (void *)incomingim_ch2_chat_free;
}

static void
incomingim_ch2_icqserverrelay_free(OscarData *od, IcbmArgsCh2 *args)
{
	g_free((char *)args->info.rtfmsg.msg);
}

/*
 * The relationship between OSCAR_CAPABILITY_ICQSERVERRELAY and OSCAR_CAPABILITY_ICQRTF is
 * kind of odd. This sends the client ICQRTF since that is all that I've seen
 * SERVERRELAY used for.
 *
 * Note that this is all little-endian.  Cringe.
 *
 */
static void
incomingim_ch2_icqserverrelay(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, aim_userinfo_t *userinfo, IcbmArgsCh2 *args, ByteStream *servdata)
{
	guint16 hdrlen, msglen;

	args->destructor = (void *)incomingim_ch2_icqserverrelay_free;

#define SKIP_HEADER(expected_hdrlen) \
	hdrlen = byte_stream_getle16(servdata); \
	if (hdrlen != expected_hdrlen) { \
		purple_debug_warning("oscar", "Expected to find a header with length " #expected_hdrlen "; ignoring message"); \
		return; \
	} \
	byte_stream_advance(servdata, hdrlen);

	SKIP_HEADER(0x001b);
	SKIP_HEADER(0x000e);

	args->info.rtfmsg.msgtype = byte_stream_get8(servdata);
	/*
	 * Copied from http://iserverd.khstu.ru/oscar/message.html:
	 * xx      byte       message flags
	 * xx xx   word (LE)  status code
	 * xx xx   word (LE)  priority code
	 *
	 * We don't need any of these, so just skip them.
	 */
	byte_stream_advance(servdata, 1 + 2 + 2);

	msglen = byte_stream_getle16(servdata);
	args->info.rtfmsg.msg = byte_stream_getstr(servdata, msglen);
}

static void
incomingim_ch2_sendfile_free(OscarData *od, IcbmArgsCh2 *args)
{
	g_free(args->info.sendfile.filename);
}

/* Someone is sending us a file */
static void
incomingim_ch2_sendfile(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, aim_userinfo_t *userinfo, IcbmArgsCh2 *args, ByteStream *servdata)
{
	int flen;

	args->destructor = (void *)incomingim_ch2_sendfile_free;

	/* Maybe there is a better way to tell what kind of sendfile
	 * this is?  Maybe TLV t(000a)? */

	/* subtype is one of AIM_OFT_SUBTYPE_* */
	args->info.sendfile.subtype = byte_stream_get16(servdata);
	args->info.sendfile.totfiles = byte_stream_get16(servdata);
	args->info.sendfile.totsize = byte_stream_get32(servdata);

	/*
	 * I hope to God I'm right when I guess that there is a
	 * 32 char max filename length for single files.  I think
	 * OFT tends to do that.  Gotta love inconsistency.  I saw
	 * a 26 byte filename?
	 */
	/* AAA - create an byte_stream_getnullstr function (don't anymore)(maybe) */
	/* Use an inelegant way of getting the null-terminated filename,
	 * since there's no easy bstream routine. */
	for (flen = 0; byte_stream_get8(servdata); flen++);
	byte_stream_advance(servdata, -flen -1);
	args->info.sendfile.filename = byte_stream_getstr(servdata, flen);

	/* There is sometimes more after the null-terminated filename,
	 * but I'm unsure of its format. */
	/* I don't believe him. */
	/* There is sometimes a null byte inside a unicode filename,
	 * but as far as I can tell the filename is the last
	 * piece of data that will be in this message. --Jonathan */
}

typedef void (*ch2_args_destructor_t)(OscarData *od, IcbmArgsCh2 *args);

static int incomingim_ch2(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, guint16 channel, aim_userinfo_t *userinfo, GSList *tlvlist, guint8 *cookie)
{
	aim_rxcallback_t userfunc;
	aim_tlv_t *block1, *servdatatlv;
	GSList *list2;
	aim_tlv_t *tlv;
	IcbmArgsCh2 args;
	ByteStream bbs, sdbs, *sdbsptr = NULL;
	guint8 *cookie2;
	int ret = 0;

	char proxyip[30] = {""};
	char clientip[30] = {""};
	char verifiedip[30] = {""};

	memset(&args, 0, sizeof(args));

	/*
	 * There's another block of TLVs embedded in the type 5 here.
	 */
	block1 = aim_tlv_gettlv(tlvlist, 0x0005, 1);
	if (block1 == NULL)
	{
		/* The server sent us ch2 ICBM without ch2 info?  Weird. */
		return 1;
	}
	byte_stream_init(&bbs, block1->value, block1->length);

	/*
	 * First two bytes represent the status of the connection.
	 * One of the AIM_RENDEZVOUS_ defines.
	 *
	 * 0 is a request, 1 is a cancel, 2 is an accept
	 */
	args.status = byte_stream_get16(&bbs);

	/*
	 * Next comes the cookie.  Should match the ICBM cookie.
	 */
	cookie2 = byte_stream_getraw(&bbs, 8);
	if (memcmp(cookie, cookie2, 8) != 0)
	{
		purple_debug_warning("oscar",
				"Cookies don't match in rendezvous ICBM, bailing out.\n");
		g_free(cookie2);
		return 1;
	}
	memcpy(args.cookie, cookie2, 8);
	g_free(cookie2);

	/*
	 * The next 16bytes are a capability block so we can
	 * identify what type of rendezvous this is.
	 */
	args.type = aim_locate_getcaps(od, &bbs, 0x10);

	/*
	 * What follows may be TLVs or nothing, depending on the
	 * purpose of the message.
	 *
	 * Ack packets for instance have nothing more to them.
	 */
	list2 = aim_tlvlist_read(&bbs);

	/*
	 * IP address to proxy the file transfer through.
	 *
	 * TODO: I don't like this.  Maybe just read in an int?  Or inet_ntoa...
	 */
	tlv = aim_tlv_gettlv(list2, 0x0002, 1);
	if ((tlv != NULL) && (tlv->length == 4))
		snprintf(proxyip, sizeof(proxyip), "%hhu.%hhu.%hhu.%hhu",
				tlv->value[0], tlv->value[1],
				tlv->value[2], tlv->value[3]);

	/*
	 * IP address from the perspective of the client.
	 */
	tlv = aim_tlv_gettlv(list2, 0x0003, 1);
	if ((tlv != NULL) && (tlv->length == 4))
		snprintf(clientip, sizeof(clientip), "%hhu.%hhu.%hhu.%hhu",
				tlv->value[0], tlv->value[1],
				tlv->value[2], tlv->value[3]);

	/*
	 * Verified IP address (from the perspective of Oscar).
	 *
	 * This is added by the server.
	 */
	tlv = aim_tlv_gettlv(list2, 0x0004, 1);
	if ((tlv != NULL) && (tlv->length == 4))
		snprintf(verifiedip, sizeof(verifiedip), "%hhu.%hhu.%hhu.%hhu",
				tlv->value[0], tlv->value[1],
				tlv->value[2], tlv->value[3]);

	/*
	 * Port number for something.
	 */
	if (aim_tlv_gettlv(list2, 0x0005, 1))
		args.port = aim_tlv_get16(list2, 0x0005, 1);

	/*
	 * File transfer "request number":
	 * 0x0001 - Initial file transfer request for no proxy or stage 1 proxy
	 * 0x0002 - "Reply request" for a stage 2 proxy (receiver wants to use proxy)
	 * 0x0003 - A third request has been sent; applies only to stage 3 proxied transfers
	 */
	if (aim_tlv_gettlv(list2, 0x000a, 1))
		args.requestnumber = aim_tlv_get16(list2, 0x000a, 1);

	/*
	 * Terminate connection/error code.  0x0001 means the other user
	 * cancelled the connection.
	 */
	if (aim_tlv_gettlv(list2, 0x000b, 1))
		args.errorcode = aim_tlv_get16(list2, 0x000b, 1);

	/*
	 * Invitation message / chat description.
	 */
	if (aim_tlv_gettlv(list2, 0x000c, 1)) {
		args.msg = aim_tlv_getstr(list2, 0x000c, 1);
		args.msglen = aim_tlv_getlength(list2, 0x000c, 1);
	}

	/*
	 * Character set.
	 */
	if (aim_tlv_gettlv(list2, 0x000d, 1))
		args.encoding = aim_tlv_getstr(list2, 0x000d, 1);

	/*
	 * Language.
	 */
	if (aim_tlv_gettlv(list2, 0x000e, 1))
		args.language = aim_tlv_getstr(list2, 0x000e, 1);

	/*
	 * Flag meaning we should proxy the file transfer through an AIM server
	 */
	if (aim_tlv_gettlv(list2, 0x0010, 1))
		args.use_proxy = TRUE;

	if (strlen(proxyip))
		args.proxyip = (char *)proxyip;
	if (strlen(clientip))
		args.clientip = (char *)clientip;
	if (strlen(verifiedip))
		args.verifiedip = (char *)verifiedip;

	/*
	 * This must be present in PROPOSALs, but will probably not
	 * exist in CANCELs and ACCEPTs.  Also exists in ICQ Lite
	 * Beta 4.0 URLs (OSCAR_CAPABILITY_ICQSERVERRELAY).
	 *
	 * Service Data blocks are module-specific in format.
	 */
	if ((servdatatlv = aim_tlv_gettlv(list2, 0x2711 /* 10001 */, 1))) {

		byte_stream_init(&sdbs, servdatatlv->value, servdatatlv->length);
		sdbsptr = &sdbs;

		/*
		 * The rest of the handling depends on what type it is.
		 *
		 * Not all of them have special handling (yet).
		 */
		if (args.type & OSCAR_CAPABILITY_BUDDYICON)
			incomingim_ch2_buddyicon(od, conn, mod, frame, snac, userinfo, &args, sdbsptr);
		else if (args.type & OSCAR_CAPABILITY_SENDBUDDYLIST)
			incomingim_ch2_buddylist(od, conn, mod, frame, snac, userinfo, &args, sdbsptr);
		else if (args.type & OSCAR_CAPABILITY_CHAT)
			incomingim_ch2_chat(od, conn, mod, frame, snac, userinfo, &args, sdbsptr);
		else if (args.type & OSCAR_CAPABILITY_ICQSERVERRELAY)
			incomingim_ch2_icqserverrelay(od, conn, mod, frame, snac, userinfo, &args, sdbsptr);
		else if (args.type & OSCAR_CAPABILITY_SENDFILE)
			incomingim_ch2_sendfile(od, conn, mod, frame, snac, userinfo, &args, sdbsptr);
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, channel, userinfo, &args);


	if (args.destructor)
		((ch2_args_destructor_t)args.destructor)(od, &args);

	g_free((char *)args.msg);
	g_free((char *)args.encoding);
	g_free((char *)args.language);

	aim_tlvlist_free(list2);

	return ret;
}

static int incomingim_ch4(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, guint16 channel, aim_userinfo_t *userinfo, GSList *tlvlist, guint8 *cookie)
{
	ByteStream meat;
	aim_rxcallback_t userfunc;
	aim_tlv_t *block;
	struct aim_incomingim_ch4_args args;
	int ret = 0;

	/*
	 * Make a bstream for the meaty part.  Yum.  Meat.
	 */
	if (!(block = aim_tlv_gettlv(tlvlist, 0x0005, 1)))
		return -1;
	byte_stream_init(&meat, block->value, block->length);

	args.uin = byte_stream_getle32(&meat);
	args.type = byte_stream_getle8(&meat);
	args.flags = byte_stream_getle8(&meat);
	if (args.type == 0x1a)
		/* There seems to be a problem with the length in SMS msgs from server, this fixed it */
		args.msglen = block->length - 6;
	else
		args.msglen = byte_stream_getle16(&meat);
	args.msg = (gchar *)byte_stream_getraw(&meat, args.msglen);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, channel, userinfo, &args);

	g_free(args.msg);

	return ret;
}

/*
 * Subtype 0x0007
 *
 * It can easily be said that parsing ICBMs is THE single
 * most difficult thing to do in the in AIM protocol.  In
 * fact, I think I just did say that.
 *
 * Below is the best damned solution I've come up with
 * over the past sixteen months of battling with it. This
 * can parse both away and normal messages from every client
 * I have access to.  Its not fast, its not clean.  But it works.
 *
 */
static int incomingim(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	guchar *cookie;
	guint16 channel;
	aim_userinfo_t userinfo;

	memset(&userinfo, 0x00, sizeof(aim_userinfo_t));

	/*
	 * Read ICBM Cookie.
	 */
	cookie = byte_stream_getraw(bs, 8);

	/*
	 * Channel ID.
	 *
	 * Channel 0x0001 is the message channel.  It is
	 * used to send basic ICBMs.
	 *
	 * Channel 0x0002 is the Rendezvous channel, which
	 * is where Chat Invitiations and various client-client
	 * connection negotiations come from.
	 *
	 * Channel 0x0003 is used for chat messages.
	 *
	 * Channel 0x0004 is used for ICQ authorization, or
	 * possibly any system notice.
	 *
	 */
	channel = byte_stream_get16(bs);

	/*
	 * Extract the standard user info block.
	 *
	 * Note that although this contains TLVs that appear contiguous
	 * with the TLVs read below, they are two different pieces.  The
	 * userinfo block contains the number of TLVs that contain user
	 * information, the rest are not even though there is no separation.
	 * You can start reading the message TLVs after aim_info_extract()
	 * parses out the standard userinfo block.
	 *
	 * That also means that TLV types can be duplicated between the
	 * userinfo block and the rest of the message, however there should
	 * never be two TLVs of the same type in one block.
	 *
	 */
	aim_info_extract(od, bs, &userinfo);

	/*
	 * From here on, its depends on what channel we're on.
	 *
	 * Technically all channels have a TLV list have this, however,
	 * for the common channel 1 case, in-place parsing is used for
	 * performance reasons (less memory allocation).
	 */
	if (channel == 1) {

		ret = incomingim_ch1(od, conn, mod, frame, snac, channel, &userinfo, bs, cookie);

	} else if (channel == 2) {
		GSList *tlvlist;

		/*
		 * Read block of TLVs (not including the userinfo data).  All
		 * further data is derived from what is parsed here.
		 */
		tlvlist = aim_tlvlist_read(bs);

		ret = incomingim_ch2(od, conn, mod, frame, snac, channel, &userinfo, tlvlist, cookie);

		aim_tlvlist_free(tlvlist);

	} else if (channel == 4) {
		GSList *tlvlist;

		tlvlist = aim_tlvlist_read(bs);
		ret = incomingim_ch4(od, conn, mod, frame, snac, channel, &userinfo, tlvlist, cookie);
		aim_tlvlist_free(tlvlist);

	} else {
		purple_debug_misc("oscar", "icbm: ICBM received on an unsupported channel.  Ignoring.  (chan = %04x)\n", channel);
	}

	aim_info_free(&userinfo);
	g_free(cookie);

	return ret;
}

/* Subtype 0x000a */
static int missedcall(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint16 channel, nummissed, reason;
	aim_userinfo_t userinfo;

	while (byte_stream_bytes_left(bs)) {

		channel = byte_stream_get16(bs);
		aim_info_extract(od, bs, &userinfo);
		nummissed = byte_stream_get16(bs);
		reason = byte_stream_get16(bs);

		if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
			 ret = userfunc(od, conn, frame, channel, &userinfo, nummissed, reason);

		aim_info_free(&userinfo);
	}

	return ret;
}

/*
 * Subtype 0x000b
 *
 * Possible codes:
 *    AIM_TRANSFER_DENY_DECLINE -- "client has declined transfer"
 *
 */
int aim_im_denytransfer(OscarData *od, const char *bn, const guchar *cookie, guint16 code)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	byte_stream_new(&bs, 8+2+1+strlen(bn)+6);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x000b, 0x0000, NULL, 0);

	byte_stream_putraw(&bs, cookie, 8);

	byte_stream_put16(&bs, 0x0002); /* channel */
	byte_stream_put8(&bs, strlen(bn));
	byte_stream_putstr(&bs, bn);

	aim_tlvlist_add_16(&tlvlist, 0x0003, code);
	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x000b, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x000b.
 * Send confirmation for a channel 2 message (Miranda wants it by default).
 */
void
aim_im_send_icq_confirmation(OscarData *od, const char *bn, const guchar *cookie)
{
	ByteStream bs;
	aim_snacid_t snacid;
	guint32 header_size, data_size;
	guint16 cookie2 = (guint16)g_random_int();

	purple_debug_misc("oscar", "Sending message ack to %s\n", bn);

	header_size = 8 + 2 + 1 + strlen(bn) + 2;
	data_size = 2 + 1 + 16 + 4*2 + 2*3 + 4*3 + 1*2 + 2*3 + 1;
	byte_stream_new(&bs, header_size + data_size);

	/* The message header. */
	aim_im_puticbm(&bs, cookie, 0x0002, bn);
	byte_stream_put16(&bs, 0x0003);	/* reason */

	/* The actual message. */
	byte_stream_putle16(&bs, 0x1b);	/* subheader #1 length */
	byte_stream_put8(&bs, 0x08);	/* protocol version */
	byte_stream_putcaps(&bs, OSCAR_CAPABILITY_EMPTY);
	byte_stream_put32(&bs, 0x3);	/* client features */
	byte_stream_put32(&bs, 0x0004);	/* DC type */
	byte_stream_put16(&bs, cookie2);	/* a cookie, chosen by fair dice roll */
	byte_stream_putle16(&bs, 0x0e);	/* header #2 len? */
	byte_stream_put16(&bs, cookie2);	/* the same cookie again */
	byte_stream_put32(&bs, 0);	/* unknown */
	byte_stream_put32(&bs, 0);	/* unknown */
	byte_stream_put32(&bs, 0);	/* unknown */
	byte_stream_put8(&bs, 0x01);	/* plain text message */
	byte_stream_put8(&bs, 0x00);	/* no message flags */
	byte_stream_put16(&bs, 0x0000);	/* no icq status */
	byte_stream_put16(&bs, 0x0100);	/* priority */
	byte_stream_putle16(&bs, 1);	/* query message len */
	byte_stream_put8(&bs, 0x00);	/* empty query message */

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x000b, 0x0000, NULL, 0);
	flap_connection_send_snac(od, flap_connection_findbygroup(od, SNAC_FAMILY_ICBM), SNAC_FAMILY_ICBM, 0x000b, snacid, &bs);
	byte_stream_destroy(&bs);
}

/*
 * Subtype 0x000b - Receive the response from an ICQ status message
 * request (in which case this contains the ICQ status message) or
 * a file transfer or direct IM request was declined.
 */
static int clientautoresp(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint16 channel, reason;
	char *bn;
	guchar *cookie;
	guint8 bnlen;
	char *xml = NULL;
	guint16 hdrlen;
	int curpos;
	guint16 num1, num2;
	PurpleAccount *account;
	PurpleBuddy *buddy;
	PurplePresence *presence;
	PurpleStatus *status;

	cookie = byte_stream_getraw(bs, 8);
	channel = byte_stream_get16(bs);
	bnlen = byte_stream_get8(bs);
	bn = byte_stream_getstr(bs, bnlen);
	reason = byte_stream_get16(bs);

	if (channel == 0x0002)
	{
		hdrlen = byte_stream_getle16(bs);
		if (hdrlen == 27 && bs->len > (27 + 51)) {
			byte_stream_advance(bs, 51);
			num1 = byte_stream_getle16(bs);
			num2 = byte_stream_getle16(bs);
			purple_debug_misc("oscar", "X-Status: num1 %hu, num2 %hu\n", num1, num2);

			if (num1 == 0x4f00 && num2 == 0x3b00) {
				byte_stream_advance(bs, 86);
				curpos = byte_stream_curpos(bs);
				xml = byte_stream_getstr(bs, bs->len - curpos);
				purple_debug_misc("oscar", "X-Status: Received XML reply\n");
				if (xml) {
					GString *xstatus;
					char *tmp1, *tmp2, *unescaped_xstatus;

					/* purple_debug_misc("oscar", "X-Status: XML reply: %s\n", xml); */

					xstatus = g_string_new(NULL);

					tmp1 = strstr(xml, "&lt;title&gt;");
					if (tmp1 != NULL) {
						tmp1 += 13;
						tmp2 = strstr(tmp1, "&lt;/title&gt;");
						if (tmp2 != NULL)
							g_string_append_len(xstatus, tmp1, tmp2 - tmp1);
					}
					tmp1 = strstr(xml, "&lt;desc&gt;");
					if (tmp1 != NULL) {
						tmp1 += 12;
						tmp2 = strstr(tmp1, "&lt;/desc&gt;");
						if (tmp2 != NULL) {
							if (xstatus->len > 0 && tmp2 > tmp1)
								g_string_append(xstatus, " - ");
							g_string_append_len(xstatus, tmp1, tmp2 - tmp1);
						}
					}
					unescaped_xstatus = purple_unescape_text(xstatus->str);
					g_string_free(xstatus, TRUE);
					if (*unescaped_xstatus) {
						purple_debug_misc("oscar", "X-Status reply: %s\n", unescaped_xstatus);
						account = purple_connection_get_account(od->gc);
						buddy = purple_find_buddy(account, bn);
						presence = purple_buddy_get_presence(buddy);
						status = purple_presence_get_status(presence, "mood");
						if (status) {
							purple_prpl_got_user_status(account, bn,
									"mood",
									PURPLE_MOOD_NAME, purple_status_get_attr_string(status, PURPLE_MOOD_NAME),
									PURPLE_MOOD_COMMENT, unescaped_xstatus, NULL);
						}
					}
					g_free(unescaped_xstatus);
				} else {
					purple_debug_misc("oscar", "X-Status: Can't get XML reply string\n");
				}
			} else {
				purple_debug_misc("oscar", "X-Status: 0x0004, 0x000b not an xstatus reply\n");
			}

		}

	} else if (channel == 0x0004) { /* ICQ message */
		switch (reason) {
			case 0x0003: { /* ICQ status message.  Maybe other stuff too, you never know with these people. */
				guint8 statusmsgtype, *msg;
				guint16 len;
				guint32 state;

				len = byte_stream_getle16(bs); /* Should be 0x001b */
				byte_stream_advance(bs, len); /* Unknown */

				len = byte_stream_getle16(bs); /* Should be 0x000e */
				byte_stream_advance(bs, len); /* Unknown */

				statusmsgtype = byte_stream_getle8(bs);
				switch (statusmsgtype) {
					case 0xe8:
						state = AIM_ICQ_STATE_AWAY;
						break;
					case 0xe9:
						state = AIM_ICQ_STATE_AWAY | AIM_ICQ_STATE_BUSY;
						break;
					case 0xea:
						state = AIM_ICQ_STATE_AWAY | AIM_ICQ_STATE_OUT;
						break;
					case 0xeb:
						state = AIM_ICQ_STATE_AWAY | AIM_ICQ_STATE_DND | AIM_ICQ_STATE_BUSY;
						break;
					case 0xec:
						state = AIM_ICQ_STATE_CHAT;
						break;
					default:
						state = 0;
						break;
				}

				byte_stream_getle8(bs); /* Unknown - 0x03 Maybe this means this is an auto-reply */
				byte_stream_getle16(bs); /* Unknown - 0x0000 */
				byte_stream_getle16(bs); /* Unknown - 0x0000 */

				len = byte_stream_getle16(bs);
				msg = byte_stream_getraw(bs, len);

				if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
					ret = userfunc(od, conn, frame, channel, bn, reason, state, msg);

				g_free(msg);
			} break;

			default: {
				if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
					ret = userfunc(od, conn, frame, channel, bn, reason);
			} break;
		} /* end switch */
	}

	g_free(cookie);
	g_free(bn);
	g_free(xml);

	return ret;
}

/*
 * Subtype 0x000c - Receive an ack after sending an ICBM. The ack contains the ICBM header of the message you sent.
 */
static int msgack(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	guint16 ch;
	guchar *cookie;
	char *bn;
	int ret = 0;

	cookie = byte_stream_getraw(bs, 8);
	ch = byte_stream_get16(bs);
	bn = byte_stream_getstr(bs, byte_stream_get8(bs));

	purple_debug_info("oscar", "Sent message to %s.\n", bn);

	g_free(bn);
	g_free(cookie);

	return ret;
}

/*
 * Subtype 0x0010 - Request any offline messages that are waiting for
 * us.  This is the "new" way of handling offline messages which is
 * used for both AIM and ICQ.  The old way is to use the ugly
 * aim_icq_reqofflinemsgs() function, but that is no longer necessary.
 *
 * We set the 0x00000100 flag on the ICBM message parameters, which
 * tells the oscar servers that we support offline messages.  When we
 * set that flag the servers do not automatically send us offline
 * messages.  Instead we must request them using this function.  This
 * should happen after sending the 0x0001/0x0002 "client online" SNAC.
 */
int aim_im_reqofflinemsgs(OscarData *od)
{
	FlapConnection *conn;

	if (!od || !(conn = flap_connection_findbygroup(od, 0x0002)))
		return -EINVAL;

	aim_genericreq_n(od, conn, SNAC_FAMILY_ICBM, 0x0010);

	return 0;
}

/*
 * Subtype 0x0014 - Send a mini typing notification (mtn) packet.
 *
 * This is supported by winaim5 and newer, MacAIM bleh and newer, iChat bleh and newer,
 * and Purple 0.60 and newer.
 *
 */
int aim_im_sendmtn(OscarData *od, guint16 channel, const char *bn, guint16 event)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, 0x0002)))
		return -EINVAL;

	if (!bn)
		return -EINVAL;

	byte_stream_new(&bs, 11 + strlen(bn) + 2);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ICBM, 0x0014, 0x0000, NULL, 0);

	/* ICBM cookie */
	byte_stream_put32(&bs, 0x00000000);
	byte_stream_put32(&bs, 0x00000000);

	/*
	 * Channel (should be 0x0001 for mtn)
	 */
	byte_stream_put16(&bs, channel);

	/*
	 * Dest buddy name
	 */
	byte_stream_put8(&bs, strlen(bn));
	byte_stream_putstr(&bs, bn);

	/*
	 * Event (should be 0x0000, 0x0001, or 0x0002 for mtn)
	 */
	byte_stream_put16(&bs, event);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_ICBM, 0x0014, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x0006 - Send eXtra Status request
 */
int icq_im_xstatus_request(OscarData *od, const char *sn)
{
	FlapConnection *conn;
	aim_snacid_t snacid;
	guchar cookie[8];
	GSList *outer_tlvlist = NULL, *inner_tlvlist = NULL;
	ByteStream bs, header, plugindata;
	PurpleAccount *account;
	const char *fmt;
	char *statxml;
	int xmllen;

	static const guint8 pluginid[] = {
		0x09, 0x46, 0x13, 0x49, 0x4C, 0x7F, 0x11, 0xD1,
		0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00
	};

	static const guint8 c_plugindata[] = {
		0x1B, 0x00, 0x0A,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0xF9, 0xD1, 0x0E, 0x00, 0xF9, 0xD1, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x01, 0x00, 0x00, 0x4F, 0x00, 0x3B, 0x60, 0xB3, 0xEF, 0xD8, 0x2A, 0x6C, 0x45, 0xA4, 0xE0, 0x9C,
		0x5A, 0x5E, 0x67, 0xE8, 0x65, 0x08, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x53, 0x63, 0x72, 0x69, 0x70,
		0x74, 0x20, 0x50, 0x6C, 0x75, 0x67, 0x2D, 0x69, 0x6E, 0x3A, 0x20, 0x52, 0x65, 0x6D, 0x6F, 0x74,
		0x65, 0x20, 0x4E, 0x6F, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x41,
		0x72, 0x72, 0x69, 0x76, 0x65, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00
	};

	if (!od || !(conn = flap_connection_findbygroup(od, 0x0004)))
		return -EINVAL;

	if (!sn)
		return -EINVAL;

	fmt = "<N><QUERY>&lt;Q&gt;&lt;PluginID&gt;srvMng&lt;/PluginID&gt;&lt;/Q&gt;</QUERY><NOTIFY>&lt;srv&gt;&lt;id&gt;cAwaySrv&lt;/id&gt;&lt;req&gt;&lt;id&gt;AwayStat&lt;/id&gt;&lt;trans&gt;2&lt;/trans&gt;&lt;senderId&gt;%s&lt;/senderId&gt;&lt;/req&gt;&lt;/srv&gt;</NOTIFY></N>\r\n";

	account = purple_connection_get_account(od->gc);

	statxml = g_strdup_printf(fmt, account->username);
	xmllen = strlen(statxml);

	aim_icbm_makecookie(cookie);

	byte_stream_new(&bs, 10 + 8 + 2 + 1 + strlen(sn) + 2
					  + 2 + 2 + 8 + 16 + 2 + 2 + 2 + 2 + 2
					  + 2 + 2 + sizeof(c_plugindata) + xmllen
					  + 2 + 2);

	snacid = aim_cachesnac(od, 0x0004, 0x0006, 0x0000, NULL, 0);
	aim_im_puticbm(&bs, cookie, 0x0002, sn);

	byte_stream_new(&header, (7*2) + 16 + 8 + 2 + sizeof(c_plugindata) + xmllen); /* TLV 0x0005 Stream + Size */
	byte_stream_put16(&header, 0x0000); /* Message Type: Request */
	byte_stream_putraw(&header, cookie, sizeof(cookie)); /* Message ID */
	byte_stream_putraw(&header, pluginid, sizeof(pluginid)); /* Plugin ID */

	aim_tlvlist_add_16(&inner_tlvlist, 0x000a, 0x0001);
	aim_tlvlist_add_noval(&inner_tlvlist, 0x000f);

	/* Add Plugin Specific Data */
	byte_stream_new(&plugindata, (sizeof(c_plugindata) + xmllen));
	byte_stream_putraw(&plugindata, c_plugindata, sizeof(c_plugindata)); /* Content of TLV 0x2711 */
	byte_stream_putraw(&plugindata, (const guint8*)statxml, xmllen);

	aim_tlvlist_add_raw(&inner_tlvlist, 0x2711, (sizeof(c_plugindata) + xmllen), plugindata.data);

	aim_tlvlist_write(&header, &inner_tlvlist);
	aim_tlvlist_free(inner_tlvlist);

	aim_tlvlist_add_raw(&outer_tlvlist, 0x0005, byte_stream_curpos(&header), header.data);
	aim_tlvlist_add_noval(&outer_tlvlist, 0x0003); /* Empty TLV 0x0003 */

	aim_tlvlist_write(&bs, &outer_tlvlist);

	purple_debug_misc("oscar", "X-Status Request\n");
	flap_connection_send_snac_with_priority(od, conn, 0x0004, 0x0006, snacid, &bs, TRUE);

	aim_tlvlist_free(outer_tlvlist);
	byte_stream_destroy(&header);
	byte_stream_destroy(&plugindata);
	byte_stream_destroy(&bs);
	g_free(statxml);

	return 0;
}

int icq_relay_xstatus(OscarData *od, const char *sn, const guchar *cookie)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	PurpleAccount *account;
	PurpleStatus *status;
	const char *fmt;
	const char *formatted_msg;
	char *msg;
	char *statxml;
	const char *title;
	int len;

	static const guint8 plugindata[] = {
		0x1B, 0x00,
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0xF9, 0xD1, 0x0E, 0x00, 0xF9, 0xD1,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x4F,
		0x00, 0x3B, 0x60, 0xB3, 0xEF, 0xD8, 0x2A, 0x6C, 0x45, 0xA4, 0xE0,
		0x9C, 0x5A, 0x5E, 0x67, 0xE8, 0x65, 0x08, 0x00, 0x2A, 0x00, 0x00,
		0x00, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x20, 0x50, 0x6C, 0x75,
		0x67, 0x2D, 0x69, 0x6E, 0x3A, 0x20, 0x52, 0x65, 0x6D, 0x6F, 0x74,
		0x65, 0x20, 0x4E, 0x6F, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
		0x69, 0x6F, 0x6E, 0x20, 0x41, 0x72, 0x72, 0x69, 0x76, 0x65, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xF3, 0x01, 0x00, 0x00, 0xEF, 0x01, 0x00, 0x00
	};

	fmt = "<NR><RES>&lt;ret event='OnRemoteNotification'&gt;&lt;srv&gt;&lt;id&gt;cAwaySrv&lt;/id&gt;&lt;val srv_id='cAwaySrv'&gt;&lt;Root&gt;&lt;CASXtraSetAwayMessage&gt;&lt;/CASXtraSetAwayMessage&gt;&l t;uin&gt;%s&lt;/uin&gt;&lt;index&gt;1&lt;/index&gt;&lt;title&gt;%s&lt;/title&gt;&lt;desc&gt;%s&lt;/desc&gt;&lt;/Root&gt;&lt;/val&gt;&lt;/srv&gt;&lt;srv&gt;&lt;id&gt;cRandomizerSrv&lt;/id&gt;&lt;val srv_id='cRandomizerSrv'&gt;undefined&lt;/val&gt;&lt;/srv&gt;&lt;/ret&gt;</RES></NR>\r\n";

	if (!od || !(conn = flap_connection_findbygroup(od, 0x0002)))
		return -EINVAL;

	if (!sn)
		return -EINVAL;

	account = purple_connection_get_account(od->gc);
	if (!account)
		return -EINVAL;

	/* if (!strcmp(account->username, sn))
		icq_im_xstatus_request(od, sn); */

	status = purple_presence_get_active_status(account->presence);
	if (!status)
		return -EINVAL;

	title = purple_status_get_name(status);
	if (!title)
		return -EINVAL;

	formatted_msg = purple_status_get_attr_string(status, "message");
	if (!formatted_msg)
		return -EINVAL;

	msg = purple_markup_strip_html(formatted_msg);
	if (!msg)
		return -EINVAL;

	statxml = g_strdup_printf(fmt, account->username, title, msg);
	len = strlen(statxml);

	purple_debug_misc("oscar", "X-Status AutoReply: %s, %s\n", formatted_msg, msg);

	byte_stream_new(&bs, 10 + 8 + 2 + 1 + strlen(sn) + 2 + sizeof(plugindata) + len); /* 16 extra */

	snacid = aim_cachesnac(od, 0x0004, 0x000b, 0x0000, NULL, 0);
	aim_im_puticbm(&bs, cookie, 0x0002, sn);
	byte_stream_put16(&bs, 0x0003);
	byte_stream_putraw(&bs, plugindata, sizeof(plugindata));
	byte_stream_putraw(&bs, (const guint8*)statxml, len);

	flap_connection_send_snac_with_priority(od, conn, 0x0004, 0x000b, snacid, &bs, TRUE);

	g_free(statxml);
	g_free(msg);
	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x0014 - Receive a mini typing notification (mtn) packet.
 *
 * This is supported by winaim5 and newer, MacAIM bleh and newer, iChat bleh and newer,
 * and Purple 0.60 and newer.
 *
 */
static int mtn_receive(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	char *bn;
	guint8 bnlen;
	guint16 channel, event;

	byte_stream_advance(bs, 8); /* ICBM cookie */
	channel = byte_stream_get16(bs);
	bnlen = byte_stream_get8(bs);
	bn = byte_stream_getstr(bs, bnlen);
	event = byte_stream_get16(bs);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, channel, bn, event);

	g_free(bn);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0001)
		return error(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0005)
		return aim_im_paraminfo(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0007)
		return incomingim(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000a)
		return missedcall(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000b)
		return clientautoresp(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000c)
		return msgack(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0014)
		return mtn_receive(od, conn, mod, frame, snac, bs);

	return 0;
}

int
msg_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_ICBM;
	mod->version = 0x0001;
	mod->toolid = 0x0110;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "messaging", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
