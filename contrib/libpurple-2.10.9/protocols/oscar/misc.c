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
 * Random stuff.  Basically just a few functions for sending
 * simple SNACs, and then the generic error handler.
 */

#include "oscar.h"

/*
 * Generic routine for sending commands.
 *
 * I know I can do this in a smarter way...but I'm not thinking straight
 * right now...
 *
 * I had one big function that handled all three cases, but then it broke
 * and I split it up into three.  But then I fixed it.  I just never went
 * back to the single.  I don't see any advantage to doing it either way.
 *
 */
void
aim_genericreq_n(OscarData *od, FlapConnection *conn, guint16 family, guint16 subtype)
{
	aim_snacid_t snacid = 0x00000000;

	flap_connection_send_snac(od, conn, family, subtype, snacid, NULL);
}

void
aim_genericreq_n_snacid(OscarData *od, FlapConnection *conn, guint16 family, guint16 subtype)
{
	aim_snacid_t snacid;

	snacid = aim_cachesnac(od, family, subtype, 0x0000, NULL, 0);

	flap_connection_send_snac(od, conn, family, subtype, snacid, NULL);
}

void
aim_genericreq_l(OscarData *od, FlapConnection *conn, guint16 family, guint16 subtype, guint32 *longdata)
{
	ByteStream bs;
	aim_snacid_t snacid;

	if (!longdata)
	{
		aim_genericreq_n(od, conn, family, subtype);
		return;
	}

	byte_stream_new(&bs, 4);

	snacid = aim_cachesnac(od, family, subtype, 0x0000, NULL, 0);

	byte_stream_put32(&bs, *longdata);

	flap_connection_send_snac(od, conn, family, subtype, snacid, &bs);

	byte_stream_destroy(&bs);
}

/*
 * Should be generic enough to handle the errors for all groups.
 *
 */
static int
generror(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	int error = 0;
	aim_rxcallback_t userfunc;
	aim_snac_t *snac2;

	snac2 = aim_remsnac(od, snac->id);

	if (byte_stream_bytes_left(bs))
		error = byte_stream_get16(bs);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, error, snac2 ? snac2->data : NULL);

	if (snac2) {
		g_free(snac2->data);
		g_free(snac2);
	}

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0001)
		return generror(od, conn, mod, frame, snac, bs);
	else if ((snac->family == 0xffff) && (snac->subtype == 0xffff)) {
		aim_rxcallback_t userfunc;

		if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
			return userfunc(od, conn, frame);
	}

	return 0;
}

int
misc_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = 0xffff;
	mod->version = 0x0000;
	mod->flags = AIM_MODFLAG_MULTIFAMILY;
	strncpy(mod->name, "misc", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
