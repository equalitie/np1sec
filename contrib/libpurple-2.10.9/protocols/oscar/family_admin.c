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
 * Family 0x0007 - Account Administration.
 *
 * Used for stuff like changing the formating of your username, changing your
 * email address, requesting an account confirmation email, getting account info,
 */

#include "oscar.h"

/**
 * Subtype 0x0002 - Request a bit of account info.
 *
 * Info should be one of the following:
 * 0x0001 - Username formatting
 * 0x0011 - Email address
 * 0x0013 - Unknown
 */
void
aim_admin_getinfo(OscarData *od, FlapConnection *conn, guint16 info)
{
	ByteStream bs;
	aim_snacid_t snacid;

	byte_stream_new(&bs, 4);

	byte_stream_put16(&bs, info);
	byte_stream_put16(&bs, 0x0000);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ADMIN, 0x0002, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ADMIN, 0x0002, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtypes 0x0003 and 0x0005 - Parse account info.
 *
 * Called in reply to both an information request (subtype 0x0002) and
 * an information change (subtype 0x0004).
 */
static void
infochange(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	char *url=NULL, *sn=NULL, *email=NULL;
	guint16 perms, tlvcount, err=0;

	perms = byte_stream_get16(bs);
	tlvcount = byte_stream_get16(bs);

	while (tlvcount && byte_stream_bytes_left(bs)) {
		guint16 type, length;

		type = byte_stream_get16(bs);
		length = byte_stream_get16(bs);

		switch (type) {
			case 0x0001: {
				g_free(sn);
				sn = byte_stream_getstr(bs, length);
			} break;

			case 0x0004: {
				g_free(url);
				url = byte_stream_getstr(bs, length);
			} break;

			case 0x0008: {
				err = byte_stream_get16(bs);
			} break;

			case 0x0011: {
				g_free(email);
				if (length == 0)
					email = g_strdup("*suppressed");
				else
					email = byte_stream_getstr(bs, length);
			} break;
		}

		tlvcount--;
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		userfunc(od, conn, frame, (snac->subtype == 0x0005) ? 1 : 0, perms, err, url, sn, email);

	g_free(sn);
	g_free(url);
	g_free(email);
}

/**
 * Subtype 0x0004 - Set the formatting of username (change spaces and capitalization).
 */
void
aim_admin_setnick(OscarData *od, FlapConnection *conn, const char *newnick)
{
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	byte_stream_new(&bs, 2+2+strlen(newnick));

	aim_tlvlist_add_str(&tlvlist, 0x0001, newnick);

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ADMIN, 0x0004, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ADMIN, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0004 - Change password.
 */
void
aim_admin_changepasswd(OscarData *od, FlapConnection *conn, const char *newpw, const char *curpw)
{
	ByteStream bs;
	GSList *tlvlist = NULL;
	aim_snacid_t snacid;

	byte_stream_new(&bs, 4+strlen(curpw)+4+strlen(newpw));

	/* new password TLV t(0002) */
	aim_tlvlist_add_str(&tlvlist, 0x0002, newpw);

	/* current password TLV t(0012) */
	aim_tlvlist_add_str(&tlvlist, 0x0012, curpw);

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ADMIN, 0x0004, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ADMIN, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Subtype 0x0004 - Change email address.
 */
void
aim_admin_setemail(OscarData *od, FlapConnection *conn, const char *newemail)
{
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	byte_stream_new(&bs, 2+2+strlen(newemail));

	aim_tlvlist_add_str(&tlvlist, 0x0011, newemail);

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_ADMIN, 0x0004, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_ADMIN, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);
}

/*
 * Subtype 0x0006 - Request account confirmation.
 *
 * This will cause an email to be sent to the address associated with
 * the account.  By following the instructions in the mail, you can
 * get the TRIAL flag removed from your account.
 *
 */
void
aim_admin_reqconfirm(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n(od, conn, SNAC_FAMILY_ADMIN, 0x0006);
}

/**
 * Subtype SNAC_FAMILY_ADMIN - Account confirmation request acknowledgement.
 */
static int
accountconfirm(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint16 status;
	/* GSList *tlvlist; */

	status = byte_stream_get16(bs);
	/* Status is 0x0013 if unable to confirm at this time */

	/* tlvlist = aim_tlvlist_read(bs); */

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, status);

	/* aim_tlvlist_free(tlvlist); */

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if ((snac->subtype == 0x0003) || (snac->subtype == 0x0005)) {
		infochange(od, conn, mod, frame, snac, bs);
		return 1;
	} else if (snac->subtype == SNAC_FAMILY_ADMIN)
		return accountconfirm(od, conn, mod, frame, snac, bs);

	return 0;
}

int admin_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_ADMIN;
	mod->version = 0x0001;
	mod->toolid = 0x0010;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "admin", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
