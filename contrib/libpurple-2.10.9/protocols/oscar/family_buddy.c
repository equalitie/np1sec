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
 * Family 0x0003 (SNAC_FAMILY_BUDDY) - Old-style Buddylist Management (non-SSI).
 *
 */

#include "oscar.h"

#include <string.h>

/*
 * Subtype 0x0002 - Request rights.
 *
 * Request Buddy List rights.
 *
 */
void
aim_buddylist_reqrights(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_BUDDY, SNAC_SUBTYPE_BUDDY_REQRIGHTS);
}

/*
 * Subtype 0x0003 - Rights.
 *
 */
static int
rights(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	GSList *tlvlist;
	guint16 maxbuddies = 0, maxwatchers = 0;
	int ret = 0;

	/*
	 * TLVs follow
	 */
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * TLV type 0x0001: Maximum number of buddies.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0001, 1))
		maxbuddies = aim_tlv_get16(tlvlist, 0x0001, 1);

	/*
	 * TLV type 0x0002: Maximum number of watchers.
	 *
	 * Watchers are other users who have you on their buddy
	 * list.  (This is called the "reverse list" by a certain
	 * other IM protocol.)
	 *
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0002, 1))
		maxwatchers = aim_tlv_get16(tlvlist, 0x0002, 1);

	/*
	 * TLV type 0x0003: Unknown.
	 *
	 * ICQ only?
	 */

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, maxbuddies, maxwatchers);

	aim_tlvlist_free(tlvlist);

	return ret;
}

/*
 * Subtypes 0x000b (SNAC_SUBTYPE_BUDDY_ONCOMING) and 0x000c (SNAC_SUBTYPE_BUDDY_OFFGOING) - Change in buddy status
 *
 * Oncoming Buddy notifications contain a subset of the
 * user information structure.  It's close enough to run
 * through aim_info_extract() however.
 *
 * Although the offgoing notification contains no information,
 * it is still in a format parsable by aim_info_extract().
 *
 */
static int
buddychange(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_userinfo_t userinfo;
	aim_rxcallback_t userfunc;

	aim_info_extract(od, bs, &userinfo);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, &userinfo);

	if (snac->subtype == SNAC_SUBTYPE_BUDDY_ONCOMING &&
	    userinfo.capabilities & OSCAR_CAPABILITY_XTRAZ) {
		PurpleAccount *account = purple_connection_get_account(od->gc);
		PurpleBuddy *buddy = purple_find_buddy(account, userinfo.bn);

		if (buddy) {
			PurplePresence *presence = purple_buddy_get_presence(buddy);

			if (purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_MOOD))
				icq_im_xstatus_request(od, userinfo.bn);
		}
	}
	aim_info_free(&userinfo);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == SNAC_SUBTYPE_BUDDY_RIGHTSINFO)
		return rights(od, conn, mod, frame, snac, bs);
	else if ((snac->subtype == SNAC_SUBTYPE_BUDDY_ONCOMING) || (snac->subtype == SNAC_SUBTYPE_BUDDY_OFFGOING))
		return buddychange(od, conn, mod, frame, snac, bs);

	return 0;
}

int
buddylist_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_BUDDY;
	mod->version = 0x0001;
	mod->toolid = 0x0110;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "buddy", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
