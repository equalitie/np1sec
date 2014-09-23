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
 * Family 0x000a - User Search.
 *
 * TODO: Add aim_usersearch_name()
 *
 */

#include "oscar.h"

/*
 * Subtype 0x0001
 *
 * XXX can this be integrated with the rest of the error handling?
 */
static int error(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	aim_snac_t *snac2;

	/* XXX the modules interface should have already retrieved this for us */
	if (!(snac2 = aim_remsnac(od, snac->id))) {
		purple_debug_misc("oscar", "search error: couldn't get a snac for 0x%08x\n", snac->id);
		return 0;
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, snac2->data /* address */);

	/* XXX freesnac()? */
	if (snac2)
		g_free(snac2->data);
	g_free(snac2);

	return ret;
}

/*
 * Subtype 0x0002
 *
 */
int aim_search_address(OscarData *od, const char *address)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_USERLOOKUP);

	if (!conn || !address)
		return -EINVAL;

	byte_stream_new(&bs, strlen(address));

	byte_stream_putstr(&bs, address);

	snacid = aim_cachesnac(od, SNAC_FAMILY_USERLOOKUP, 0x0002, 0x0000, address, strlen(address)+1);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_USERLOOKUP, 0x0002, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x0003
 *
 */
static int reply(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int j = 0, m, ret = 0;
	GSList *tlvlist;
	char *cur = NULL, *buf = NULL;
	aim_rxcallback_t userfunc;
	aim_snac_t *snac2;
	const char *searchaddr = NULL;

	if ((snac2 = aim_remsnac(od, snac->id)))
		searchaddr = (const char *)snac2->data;

	tlvlist = aim_tlvlist_read(bs);
	m = aim_tlvlist_count(tlvlist);

	/* XXX uhm.
	 * This is the only place that uses something other than 1 for the 3rd
	 * parameter to aim_tlv_gettlv_whatever().
	 */
	while ((cur = aim_tlv_getstr(tlvlist, 0x0001, j+1)) && j < m)
	{
		buf = g_realloc(buf, (j+1) * (MAXSNLEN+1));

		strncpy(&buf[j * (MAXSNLEN+1)], cur, MAXSNLEN);
		g_free(cur);

		j++;
	}
	g_free(cur);

	aim_tlvlist_free(tlvlist);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, searchaddr, j, buf);

	/* XXX freesnac()? */
	if (snac2)
		g_free(snac2->data);
	g_free(snac2);

	g_free(buf);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0001)
		return error(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0003)
		return reply(od, conn, mod, frame, snac, bs);

	return 0;
}

int
search_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_USERLOOKUP;
	mod->version = 0x0001;
	mod->toolid = 0x0110;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "userlookup", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
