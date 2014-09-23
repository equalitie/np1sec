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
 * Family 0x0009 - Basic Oscar Service.
 *
 * The functionality of this family has been replaced by SSI.
 */

#include "oscar.h"

#include <string.h>

/* Subtype 0x0002 - Request BOS rights. */
void
aim_bos_reqrights(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_BOS, 0x0002);
}

/* Subtype 0x0003 - BOS Rights. */
static int rights(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	GSList *tlvlist;
	guint16 maxpermits = 0, maxdenies = 0;
	int ret = 0;

	/*
	 * TLVs follow
	 */
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * TLV type 0x0001: Maximum number of buddies on permit list.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0001, 1))
		maxpermits = aim_tlv_get16(tlvlist, 0x0001, 1);

	/*
	 * TLV type 0x0002: Maximum number of buddies on deny list.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0002, 1))
		maxdenies = aim_tlv_get16(tlvlist, 0x0002, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, maxpermits, maxdenies);

	aim_tlvlist_free(tlvlist);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0003)
		return rights(od, conn, mod, frame, snac, bs);

	return 0;
}

int
bos_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_BOS;
	mod->version = 0x0001;
	mod->toolid = 0x0110;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "bos", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
