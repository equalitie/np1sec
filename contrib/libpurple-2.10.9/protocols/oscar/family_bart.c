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
 * Family 0x0010 - Server stored buddy art
 *
 * Used for storing and retrieving your cute little buddy icon
 * from the AIM servers.
 *
 */

#include "oscar.h"

/**
 * Subtype 0x0002 - Upload your icon.
 *
 * @param od The oscar session.
 * @param icon The raw data of the icon image file.
 * @param iconlen Length of the raw data of the icon image file.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_bart_upload(OscarData *od, const guint8 *icon, guint16 iconlen)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_BART)) || !icon || !iconlen)
		return -EINVAL;

	byte_stream_new(&bs, 2 + 2 + iconlen);

	/* The reference number for the icon */
	byte_stream_put16(&bs, 1);

	/* The icon */
	byte_stream_put16(&bs, iconlen);
	byte_stream_putraw(&bs, icon, iconlen);

	snacid = aim_cachesnac(od, SNAC_FAMILY_BART, 0x0002, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_BART, 0x0002, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/**
 * Subtype 0x0003 - Acknowledgement for uploading a buddy icon.
 *
 * You get this honky after you upload a buddy icon.
 */
static int
uploadack(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint16 something, somethingelse;
	guint8 onemorething;

	something = byte_stream_get16(bs);
	somethingelse = byte_stream_get16(bs);
	onemorething = byte_stream_get8(bs);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame);

	return ret;
}

/**
 * Subtype 0x0004 - Request someone's icon.
 *
 * @param od The oscar session.
 * @param bn The name of the buddy whose icon you are requesting.
 * @param iconcsum The MD5 checksum of the icon you are requesting.
 * @param iconcsumlen Length of the MD5 checksum given above.  Should be 10 bytes.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_bart_request(OscarData *od, const char *bn, guint8 iconcsumtype, const guint8 *iconcsum, guint16 iconcsumlen)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_BART)) || !bn || !strlen(bn) || !iconcsum || !iconcsumlen)
		return -EINVAL;

	byte_stream_new(&bs, 1+strlen(bn) + 4 + 1+iconcsumlen);

	/* Buddy name */
	byte_stream_put8(&bs, strlen(bn));
	byte_stream_putstr(&bs, bn);

	/* Some numbers.  You like numbers, right? */
	byte_stream_put8(&bs, 0x01);
	byte_stream_put16(&bs, 0x0001);
	byte_stream_put8(&bs, iconcsumtype);

	/* Icon string */
	byte_stream_put8(&bs, iconcsumlen);
	byte_stream_putraw(&bs, iconcsum, iconcsumlen);

	snacid = aim_cachesnac(od, SNAC_FAMILY_BART, 0x0004, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_BART, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/**
 * Subtype 0x0005 - Receive a buddy icon.
 *
 * This is sent in response to a buddy icon request.
 */
static int
parseicon(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	char *bn;
	guint16 flags, iconlen;
	guint8 iconcsumtype, iconcsumlen, *iconcsum, *icon;

	bn = byte_stream_getstr(bs, byte_stream_get8(bs));
	flags = byte_stream_get16(bs);
	iconcsumtype = byte_stream_get8(bs);
	iconcsumlen = byte_stream_get8(bs);
	iconcsum = byte_stream_getraw(bs, iconcsumlen);
	iconlen = byte_stream_get16(bs);
	icon = byte_stream_getraw(bs, iconlen);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, bn, iconcsumtype, iconcsum, iconcsumlen, icon, iconlen);

	g_free(bn);
	g_free(iconcsum);
	g_free(icon);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0003)
		return uploadack(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0005)
		return parseicon(od, conn, mod, frame, snac, bs);

	return 0;
}

int
bart_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_BART;
	mod->version = 0x0001;
	mod->toolid = 0x0010;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "bart", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
