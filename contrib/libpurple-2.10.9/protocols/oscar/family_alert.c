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
 * Family 0x0018 - Email notification
 *
 * Used for being alerted when the email address(es) associated with
 * your username get new electronic-m.  For normal AIM accounts, you
 * get the email address username@netscape.net.  AOL accounts have
 * username@aol.com, and can also activate a netscape.net account.
 * Note: This information might be out of date.
 */

#include "oscar.h"

/**
 * Subtype 0x0006 - Request information about your email account
 *
 * @param od The oscar session.
 * @param conn The email connection for this session.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_email_sendcookies(OscarData *od)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ALERT)))
		return -EINVAL;

	byte_stream_new(&bs, 2+16+16);

	/* Number of cookies to follow */
	byte_stream_put16(&bs, 0x0002);

	/* Cookie */
	byte_stream_put16(&bs, 0x5d5e);
	byte_stream_put16(&bs, 0x1708);
	byte_stream_put16(&bs, 0x55aa);
	byte_stream_put16(&bs, 0x11d3);
	byte_stream_put16(&bs, 0xb143);
	byte_stream_put16(&bs, 0x0060);
	byte_stream_put16(&bs, 0xb0fb);
	byte_stream_put16(&bs, 0x1ecb);

	/* Cookie */
	byte_stream_put16(&bs, 0xb380);
	byte_stream_put16(&bs, 0x9ad8);
	byte_stream_put16(&bs, 0x0dba);
	byte_stream_put16(&bs, 0x11d5);
	byte_stream_put16(&bs, 0x9f8a);
	byte_stream_put16(&bs, 0x0060);
	byte_stream_put16(&bs, 0xb0ee);
	byte_stream_put16(&bs, 0x0631);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ALERT, 0x0006, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ALERT, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}


/**
 * Subtype 0x0007 - Receive information about your email account
 *
 * So I don't even know if you can have multiple 16 byte keys,
 * but this is coded so it will handle that, and handle it well.
 * This tells you if you have unread mail or not, the URL you
 * should use to access that mail, and the domain name for the
 * email account (username@domainname.com).  If this is the
 * first 0x0007 SNAC you've received since you signed on, or if
 * this is just a periodic status update, this will also contain
 * the number of unread emails that you have.
 */
static int
parseinfo(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	struct aim_emailinfo *new;
	GSList *tlvlist;
	guint8 *cookie8, *cookie16;
	int tmp, havenewmail = 0; /* Used to tell the client we have _new_ mail */

	char *alertitle = NULL, *alerturl = NULL;

	cookie8 = byte_stream_getraw(bs, 8); /* Possibly the code used to log you in to mail? */
	cookie16 = byte_stream_getraw(bs, 16); /* Mail cookie sent above */

	/* See if we already have some info associated with this cookie */
	for (new = od->emailinfo; (new && memcmp(cookie16, new->cookie16, 16)); new = new->next);
	if (new) {
		/* Free some of the old info, if it exists */
		g_free(new->cookie8);
		g_free(new->cookie16);
		g_free(new->url);
		g_free(new->domain);
	} else {
		/* We don't already have info, so create a new struct for it */
		new = g_new0(struct aim_emailinfo, 1);
		new->next = od->emailinfo;
		od->emailinfo = new;
	}

	new->cookie8 = cookie8;
	new->cookie16 = cookie16;

	tlvlist = aim_tlvlist_readnum(bs, byte_stream_get16(bs));

	tmp = aim_tlv_get16(tlvlist, 0x0080, 1);
	if (tmp) {
		if (new->nummsgs < tmp)
			havenewmail = 1;
		new->nummsgs = tmp;
	} else {
		/* If they don't send a 0x0080 TLV, it means we definitely have new mail */
		/* (ie. this is not just another status update) */
		havenewmail = 1;
		new->nummsgs++; /* We know we have at least 1 new email */
	}
	new->url = aim_tlv_getstr(tlvlist, 0x0007, 1);
	if (!(new->unread = aim_tlv_get8(tlvlist, 0x0081, 1))) {
		havenewmail = 0;
		new->nummsgs = 0;
	}
	new->domain = aim_tlv_getstr(tlvlist, 0x0082, 1);
	new->flag = aim_tlv_get16(tlvlist, 0x0084, 1);

	alertitle = aim_tlv_getstr(tlvlist, 0x0005, 1);
	alerturl  = aim_tlv_getstr(tlvlist, 0x000d, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, new, havenewmail, alertitle, (alerturl ? alerturl + 2 : NULL));

	aim_tlvlist_free(tlvlist);

	g_free(alertitle);
	g_free(alerturl);

	return ret;
}

/**
 * Subtype 0x0016 - Send something or other
 *
 * @param od The oscar session.
 * @param conn The email connection for this session.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_email_activate(OscarData *od)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ALERT)))
		return -EINVAL;

	byte_stream_new(&bs, 1+16);

	/* I would guess this tells AIM that you want updates for your mail accounts */
	/* ...but I really have no idea */
	byte_stream_put8(&bs, 0x02);
	byte_stream_put32(&bs, 0x04000000);
	byte_stream_put32(&bs, 0x04000000);
	byte_stream_put32(&bs, 0x04000000);
	byte_stream_put32(&bs, 0x00000000);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ALERT, 0x0016, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ALERT, 0x0006, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0007)
		return parseinfo(od, conn, mod, frame, snac, bs);

	return 0;
}

static void
email_shutdown(OscarData *od, aim_module_t *mod)
{
	while (od->emailinfo)
	{
		struct aim_emailinfo *tmp = od->emailinfo;
		od->emailinfo = od->emailinfo->next;
		g_free(tmp->cookie16);
		g_free(tmp->cookie8);
		g_free(tmp->url);
		g_free(tmp->domain);
		g_free(tmp);
	}

	return;
}

int
email_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_ALERT;
	mod->version = 0x0001;
	mod->toolid = 0x0010;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "alert", sizeof(mod->name));
	mod->snachandler = snachandler;
	mod->shutdown = email_shutdown;

	return 0;
}
