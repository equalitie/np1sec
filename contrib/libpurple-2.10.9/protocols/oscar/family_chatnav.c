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
 * Family 0x000d - Handle ChatNav.
 *
 * The ChatNav(igation) service does various things to keep chat
 * alive.  It provides room information, room searching and creating,
 * as well as giving users the right ("permission") to use chat.
 *
 */

#include "oscar.h"

static int
error(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_snac_t *snac2;
	guint16 error, chatnav_error;
	GSList *tlvlist;

	snac2 = aim_remsnac(od, snac->id);
	if (!snac2) {
		purple_debug_warning("oscar", "chatnav error: received response to unknown request (%08x)\n", snac->id);
		return 0;
	}

	if (snac2->family != SNAC_FAMILY_CHATNAV) {
		purple_debug_warning("oscar", "chatnav error: received response that maps to corrupt request (fam=%04x)\n", snac2->family);
		g_free(snac2->data);
		g_free(snac2);
		return 0;
	}

	/*
	 * We now know what the original SNAC subtype was.
	 */
	if (snac2->type == 0x0008) /* create room */
	{
		error = byte_stream_get16(bs);
		tlvlist = aim_tlvlist_read(bs);
		chatnav_error = aim_tlv_get16(tlvlist, 0x0008, 1);

		purple_debug_warning("oscar",
				"Could not join room, error=0x%04hx, chatnav_error=0x%04hx\n",
				error, chatnav_error);
		purple_notify_error(od->gc, NULL, _("Could not join chat room"),
				chatnav_error == 0x0033 ? _("Invalid chat room name") : _("Unknown error"));

		ret = 1;
	}

	g_free(snac2->data);
	g_free(snac2);

	return ret;
}

/*
 * Subtype 0x0002
 *
 * conn must be a chatnav connection!
 *
 */
void aim_chatnav_reqrights(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_CHATNAV, 0x0002);
}

/*
 * Subtype 0x0008
 */
int aim_chatnav_createroom(OscarData *od, FlapConnection *conn, const char *name, guint16 exchange)
{
	static const char ck[] = {"create"};
	static const char lang[] = {"en"};
	static const char charset[] = {"us-ascii"};
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	byte_stream_new(&bs, 1142);

	snacid = aim_cachesnac(od, SNAC_FAMILY_CHATNAV, 0x0008, 0x0000, NULL, 0);

	/* exchange */
	byte_stream_put16(&bs, exchange);

	/*
	 * This looks to be a big hack.  You'll note that this entire
	 * SNAC is just a room info structure, but the hard room name,
	 * here, is set to "create".
	 *
	 * Either this goes on the "list of questions concerning
	 * why-the-hell-did-you-do-that", or this value is completely
	 * ignored.  Without experimental evidence, but a good knowledge of
	 * AOL style, I'm going to guess that it is the latter, and that
	 * the value of the room name in create requests is ignored.
	 */
	byte_stream_put8(&bs, strlen(ck));
	byte_stream_putstr(&bs, ck);

	/*
	 * instance
	 *
	 * Setting this to 0xffff apparently assigns the last instance.
	 *
	 */
	byte_stream_put16(&bs, 0xffff);

	/* detail level */
	byte_stream_put8(&bs, 0x01);

	aim_tlvlist_add_str(&tlvlist, 0x00d3, name);
	aim_tlvlist_add_str(&tlvlist, 0x00d6, charset);
	aim_tlvlist_add_str(&tlvlist, 0x00d7, lang);

	/* tlvcount */
	byte_stream_put16(&bs, aim_tlvlist_count(tlvlist));
	aim_tlvlist_write(&bs, &tlvlist);

	aim_tlvlist_free(tlvlist);

	flap_connection_send_snac(od, conn, SNAC_FAMILY_CHATNAV, 0x0008, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

static int
parseinfo_perms(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs, aim_snac_t *snac2)
{
	aim_rxcallback_t userfunc;
	int ret = 0;
	struct aim_chat_exchangeinfo *exchanges = NULL;
	int curexchange;
	aim_tlv_t *exchangetlv;
	guint8 maxrooms = 0;
	GSList *tlvlist, *innerlist;

	tlvlist = aim_tlvlist_read(bs);

	/*
	 * Type 0x0002: Maximum concurrent rooms.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0002, 1))
		maxrooms = aim_tlv_get8(tlvlist, 0x0002, 1);

	/*
	 * Type 0x0003: Exchange information
	 *
	 * There can be any number of these, each one
	 * representing another exchange.
	 *
	 */
	for (curexchange = 0; ((exchangetlv = aim_tlv_gettlv(tlvlist, 0x0003, curexchange+1))); ) {
		ByteStream tbs;

		byte_stream_init(&tbs, exchangetlv->value, exchangetlv->length);

		curexchange++;

		exchanges = g_realloc(exchanges, curexchange * sizeof(struct aim_chat_exchangeinfo));

		/* exchange number */
		exchanges[curexchange-1].number = byte_stream_get16(&tbs);
		innerlist = aim_tlvlist_read(&tbs);

		/*
		 * Type 0x0002: Unknown
		 */
		if (aim_tlv_gettlv(innerlist, 0x0002, 1)) {
			guint16 classperms;

			classperms = aim_tlv_get16(innerlist, 0x0002, 1);

			purple_debug_misc("oscar", "faim: class permissions %x\n", classperms);
		}

		/*
		 * Type 0x00c9: Flags
		 *
		 * 1 Evilable
		 * 2 Nav Only
		 * 4 Instancing Allowed
		 * 8 Occupant Peek Allowed
		 *
		 */
		if (aim_tlv_gettlv(innerlist, 0x00c9, 1))
			exchanges[curexchange-1].flags = aim_tlv_get16(innerlist, 0x00c9, 1);

		/*
		 * Type 0x00d3: Exchange Description
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d3, 1))
			exchanges[curexchange-1].name = aim_tlv_getstr(innerlist, 0x00d3, 1);
		else
			exchanges[curexchange-1].name = NULL;

		/*
		 * Type 0x00d5: Creation Permissions
		 *
		 * 0  Creation not allowed
		 * 1  Room creation allowed
		 * 2  Exchange creation allowed
		 *
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d5, 1)) {
			guint8 createperms;

			createperms = aim_tlv_get8(innerlist, 0x00d5, 1);
		}

		/*
		 * Type 0x00d6: Character Set (First Time)
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d6, 1))
			exchanges[curexchange-1].charset1 = aim_tlv_getstr(innerlist, 0x00d6, 1);
		else
			exchanges[curexchange-1].charset1 = NULL;

		/*
		 * Type 0x00d7: Language (First Time)
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d7, 1))
			exchanges[curexchange-1].lang1 = aim_tlv_getstr(innerlist, 0x00d7, 1);
		else
			exchanges[curexchange-1].lang1 = NULL;

		/*
		 * Type 0x00d8: Character Set (Second Time)
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d8, 1))
			exchanges[curexchange-1].charset2 = aim_tlv_getstr(innerlist, 0x00d8, 1);
		else
			exchanges[curexchange-1].charset2 = NULL;

		/*
		 * Type 0x00d9: Language (Second Time)
		 */
		if (aim_tlv_gettlv(innerlist, 0x00d9, 1))
			exchanges[curexchange-1].lang2 = aim_tlv_getstr(innerlist, 0x00d9, 1);
		else
			exchanges[curexchange-1].lang2 = NULL;

		aim_tlvlist_free(innerlist);
	}

	/*
	 * Call client.
	 */
	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, snac2->type, maxrooms, curexchange, exchanges);

	for (curexchange--; curexchange >= 0; curexchange--) {
		g_free(exchanges[curexchange].name);
		g_free(exchanges[curexchange].charset1);
		g_free(exchanges[curexchange].lang1);
		g_free(exchanges[curexchange].charset2);
		g_free(exchanges[curexchange].lang2);
	}
	g_free(exchanges);
	aim_tlvlist_free(tlvlist);

	return ret;
}

static int
parseinfo_create(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs, aim_snac_t *snac2)
{
	aim_rxcallback_t userfunc;
	GSList *tlvlist, *innerlist;
	char *ck = NULL, *fqcn = NULL, *name = NULL;
	guint16 exchange = 0, instance = 0, unknown = 0, flags = 0, maxmsglen = 0, maxoccupancy = 0;
	guint32 createtime = 0;
	guint8 createperms = 0, detaillevel;
	int cklen;
	aim_tlv_t *bigblock;
	int ret = 0;
	ByteStream bbbs;

	tlvlist = aim_tlvlist_read(bs);

	if (!(bigblock = aim_tlv_gettlv(tlvlist, 0x0004, 1))) {
		purple_debug_misc("oscar", "no bigblock in top tlv in create room response\n");
		aim_tlvlist_free(tlvlist);
		return 0;
	}

	byte_stream_init(&bbbs, bigblock->value, bigblock->length);

	exchange = byte_stream_get16(&bbbs);
	cklen = byte_stream_get8(&bbbs);
	ck = byte_stream_getstr(&bbbs, cklen);
	instance = byte_stream_get16(&bbbs);
	detaillevel = byte_stream_get8(&bbbs);

	if (detaillevel != 0x02) {
		purple_debug_misc("oscar", "unknown detaillevel in create room response (0x%02x)\n", detaillevel);
		aim_tlvlist_free(tlvlist);
		g_free(ck);
		return 0;
	}

	unknown = byte_stream_get16(&bbbs);

	innerlist = aim_tlvlist_read(&bbbs);

	if (aim_tlv_gettlv(innerlist, 0x006a, 1))
		fqcn = aim_tlv_getstr(innerlist, 0x006a, 1);

	if (aim_tlv_gettlv(innerlist, 0x00c9, 1))
		flags = aim_tlv_get16(innerlist, 0x00c9, 1);

	if (aim_tlv_gettlv(innerlist, 0x00ca, 1))
		createtime = aim_tlv_get32(innerlist, 0x00ca, 1);

	if (aim_tlv_gettlv(innerlist, 0x00d1, 1))
		maxmsglen = aim_tlv_get16(innerlist, 0x00d1, 1);

	if (aim_tlv_gettlv(innerlist, 0x00d2, 1))
		maxoccupancy = aim_tlv_get16(innerlist, 0x00d2, 1);

	if (aim_tlv_gettlv(innerlist, 0x00d3, 1))
		name = aim_tlv_getstr(innerlist, 0x00d3, 1);

	if (aim_tlv_gettlv(innerlist, 0x00d5, 1))
		createperms = aim_tlv_get8(innerlist, 0x00d5, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype))) {
		ret = userfunc(od, conn, frame, snac2->type, fqcn, instance, exchange, flags, createtime, maxmsglen, maxoccupancy, createperms, unknown, name, ck);
	}

	g_free(ck);
	g_free(name);
	g_free(fqcn);
	aim_tlvlist_free(innerlist);
	aim_tlvlist_free(tlvlist);

	return ret;
}

/*
 * Subtype 0x0009
 *
 * Since multiple things can trigger this callback, we must lookup the
 * snacid to determine the original snac subtype that was called.
 *
 * XXX This isn't really how this works.  But this is:  Every d/9 response
 * has a 16bit value at the beginning. That matches to:
 *    Short Desc = 1
 *    Full Desc = 2
 *    Instance Info = 4
 *    Nav Short Desc = 8
 *    Nav Instance Info = 16
 * And then everything is really asynchronous.  There is no specific
 * attachment of a response to a create room request, for example.  Creating
 * the room yields no different a response than requesting the room's info.
 *
 */
static int
parseinfo(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_snac_t *snac2;
	int ret = 0;

	if (!(snac2 = aim_remsnac(od, snac->id))) {
		purple_debug_misc("oscar", "faim: chatnav_parse_info: received response to unknown request! (%08x)\n", snac->id);
		return 0;
	}

	if (snac2->family != SNAC_FAMILY_CHATNAV) {
		purple_debug_misc("oscar", "faim: chatnav_parse_info: received response that maps to corrupt request! (fam=%04x)\n", snac2->family);
		g_free(snac2->data);
		g_free(snac2);
		return 0;
	}

	/*
	 * We now know what the original SNAC subtype was.
	 */
	if (snac2->type == 0x0002) /* request chat rights */
		ret = parseinfo_perms(od, conn, mod, frame, snac, bs, snac2);
	else if (snac2->type == 0x0003) /* request exchange info */
		purple_debug_misc("oscar", "chatnav_parse_info: response to exchange info\n");
	else if (snac2->type == 0x0004) /* request room info */
		purple_debug_misc("oscar", "chatnav_parse_info: response to room info\n");
	else if (snac2->type == 0x0005) /* request more room info */
		purple_debug_misc("oscar", "chatnav_parse_info: response to more room info\n");
	else if (snac2->type == 0x0006) /* request occupant list */
		purple_debug_misc("oscar", "chatnav_parse_info: response to occupant info\n");
	else if (snac2->type == 0x0007) /* search for a room */
		purple_debug_misc("oscar", "chatnav_parse_info: search results\n");
	else if (snac2->type == 0x0008) /* create room */
		ret = parseinfo_create(od, conn, mod, frame, snac, bs, snac2);
	else
		purple_debug_misc("oscar", "chatnav_parse_info: unknown request subtype (%04x)\n", snac2->type);

	if (snac2)
		g_free(snac2->data);
	g_free(snac2);

	return ret;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0001)
		return error(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0009)
		return parseinfo(od, conn, mod, frame, snac, bs);

	return 0;
}

int
chatnav_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_CHATNAV;
	mod->version = 0x0001;
	mod->toolid = 0x0010;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "chatnav", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
