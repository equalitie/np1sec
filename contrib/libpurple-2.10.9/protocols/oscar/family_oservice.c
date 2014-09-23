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
 * Family 0x0001 - This is a very special group.  All connections support
 * this group, as it does some particularly good things (like rate limiting).
 */

#include "oscar.h"

#include "cipher.h"

/*
 * Each time we make a FLAP connection to an oscar server the server gives
 * us a list of rate classes.  Each rate class has different properties for
 * how frequently we can send SNACs in that rate class before we become
 * throttled or disconnected.
 *
 * The server also gives us a list of every available SNAC and tells us which
 * rate class it's in.  There are a lot of different SNACs, so this list can be
 * fairly large.  One important characteristic of these rate classes is that
 * currently (and since at least 2004) most SNACs are in the same rate class.
 *
 * One optimization we can do to save memory is to only keep track of SNACs
 * that are in classes other than this default rate class.  So if we try to
 * look up a SNAC and it's not in our hash table then we can assume that it's
 * in the default rate class.
 */
#define OSCAR_DEFAULT_RATECLASS 1

/* Subtype 0x0002 - Client Online */
void
aim_srv_clientready(OscarData *od, FlapConnection *conn)
{
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *cur;

	byte_stream_new(&bs, 1142);

	/*
	 * Send only the tool versions that the server cares about (that it
	 * marked as supporting in the server ready SNAC).
	 */
	for (cur = conn->groups; cur != NULL; cur = cur->next)
	{
		aim_module_t *mod;

		if ((mod = aim__findmodulebygroup(od, GPOINTER_TO_UINT(cur->data))))
		{
			byte_stream_put16(&bs, mod->family);
			byte_stream_put16(&bs, mod->version);
			byte_stream_put16(&bs, mod->toolid);
			byte_stream_put16(&bs, mod->toolversion);
		}
	}

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0002, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0002, snacid, &bs);

	byte_stream_destroy(&bs);
}

/*
 * Subtype 0x0003 - Host Online
 *
 * See comments in conn.c about how the group associations are supposed
 * to work, and how they really work.
 *
 * This info probably doesn't even need to make it to the client.
 *
 * We don't actually call the client here.  This starts off the connection
 * initialization routine required by all AIM connections.  The next time
 * the client is called is the CONNINITDONE callback, which should be
 * shortly after the rate information is acknowledged.
 *
 */
static int
hostonline(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int group;

	while (byte_stream_bytes_left(bs))
	{
		group = byte_stream_get16(bs);
		conn->groups = g_slist_prepend(conn->groups, GUINT_TO_POINTER(group));
	}

	/*
	 * Next step is in the Host Versions handler.
	 *
	 * Note that we must send this before we request rates, since
	 * the format of the rate information depends on the versions we
	 * give it.
	 *
	 */
	aim_srv_setversions(od, conn);

	return 1;
}

/* Subtype 0x0004 - Service request */
void
aim_srv_requestnew(OscarData *od, guint16 serviceid)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_BOS);
	if(!conn)
		return;

	byte_stream_new(&bs, 6);

	byte_stream_put16(&bs, serviceid);

	if (od->use_ssl)
		/* Request SSL Connection */
		aim_tlvlist_add_noval(&tlvlist, 0x008c);

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0004, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);
}

/*
 * Join a room of name roomname.  This is the first step to joining an
 * already created room.  It's basically a Service Request for
 * family 0x000e, with a little added on to specify the exchange and room
 * name.
 */
int
aim_chat_join(OscarData *od, guint16 exchange, const char *roomname, guint16 instance)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;
	struct chatsnacinfo csi;

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_BOS);
	if (!conn || !roomname || roomname[0] == '\0')
		return -EINVAL;

	byte_stream_new(&bs, 506);

	memset(&csi, 0, sizeof(csi));
	csi.exchange = exchange;
	g_strlcpy(csi.name, roomname, sizeof(csi.name));
	csi.instance = instance;

	/*
	 * Requesting service chat (0x000e)
	 */
	byte_stream_put16(&bs, 0x000e);

	aim_tlvlist_add_chatroom(&tlvlist, 0x0001, exchange, roomname, instance);

	if (od->use_ssl)
		/* Request SSL Connection */
		aim_tlvlist_add_noval(&tlvlist, 0x008c);

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0004, 0x0000, &csi, sizeof(csi));
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0004, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/* Subtype 0x0005 - Redirect */
static int
redirect(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	struct aim_redirect_data redir;
	aim_rxcallback_t userfunc;
	GSList *tlvlist;
	aim_snac_t *origsnac = NULL;
	int ret = 0;

	memset(&redir, 0, sizeof(redir));

	tlvlist = aim_tlvlist_read(bs);

	if (!aim_tlv_gettlv(tlvlist, 0x000d, 1) ||
			!aim_tlv_gettlv(tlvlist, 0x0005, 1) ||
			!aim_tlv_gettlv(tlvlist, 0x0006, 1)) {
		aim_tlvlist_free(tlvlist);
		return 0;
	}

	redir.group = aim_tlv_get16(tlvlist, 0x000d, 1);
	redir.ip = aim_tlv_getstr(tlvlist, 0x0005, 1);
	redir.cookielen = aim_tlv_gettlv(tlvlist, 0x0006, 1)->length;
	redir.cookie = (guchar *)aim_tlv_getstr(tlvlist, 0x0006, 1);
	redir.ssl_cert_cn = aim_tlv_getstr(tlvlist, 0x008d, 1);
	redir.use_ssl = aim_tlv_get8(tlvlist, 0x008e, 1);

	/* Fetch original SNAC so we can get csi if needed */
	origsnac = aim_remsnac(od, snac->id);

	if ((redir.group == SNAC_FAMILY_CHAT) && origsnac) {
		struct chatsnacinfo *csi = (struct chatsnacinfo *)origsnac->data;

		redir.chat.exchange = csi->exchange;
		redir.chat.room = csi->name;
		redir.chat.instance = csi->instance;
	}

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, &redir);

	g_free((void *)redir.ip);
	g_free((void *)redir.cookie);
	g_free((void *)redir.ssl_cert_cn);

	if (origsnac)
		g_free(origsnac->data);
	g_free(origsnac);

	aim_tlvlist_free(tlvlist);

	return ret;
}

/* Subtype 0x0006 - Request Rate Information. */
void
aim_srv_reqrates(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_OSERVICE, 0x0006);
}

/*
 * OSCAR defines several 'rate classes'.  Each class has separate
 * rate limiting properties (limit level, alert level, disconnect
 * level, etc), and a set of SNAC family/type pairs associated with
 * it.  The rate classes, their limiting properties, and the definitions
 * of which SNACs belong to which class are defined in the
 * Rate Response packet at login to each host.
 *
 * Logically, all rate offenses within one class count against further
 * offenses for other SNACs in the same class (ie, sending messages
 * too fast will limit the number of user info requests you can send,
 * since those two SNACs are in the same rate class).
 *
 * Since the rate classes are defined dynamically at login, the values
 * below may change. But they seem to be fairly constant.
 *
 * Currently, BOS defines five rate classes, with the commonly used
 * members as follows...
 *
 *  Rate class 0x0001:
 *	- Everything thats not in any of the other classes
 *
 *  Rate class 0x0002:
 *	- Buddy list add/remove
 *	- Permit list add/remove
 *	- Deny list add/remove
 *
 *  Rate class 0x0003:
 *	- User information requests
 *	- Outgoing ICBMs
 *
 *  Rate class 0x0004:
 *	- A few unknowns: 2/9, 2/b, and f/2
 *
 *  Rate class 0x0005:
 *	- Chat room create
 *	- Outgoing chat ICBMs
 *
 * The only other thing of note is that class 5 (chat) has slightly looser
 * limiting properties than class 3 (normal messages).  But thats just a
 * small bit of trivia for you.
 *
 * The last thing that needs to be learned about the rate limiting
 * system is how the actual numbers relate to the passing of time.  This
 * seems to be a big mystery.
 *
 * See joscar's javadoc for the RateClassInfo class for a great
 * explanation.  You might be able to find it at
 * http://dscoder.com/RateClassInfo.html
 */

static struct rateclass *
rateclass_find(GSList *rateclasses, guint16 id)
{
	GSList *tmp;

	for (tmp = rateclasses; tmp != NULL; tmp = tmp->next)
	{
		struct rateclass *rateclass;
		rateclass = tmp->data;
		if (rateclass->classid == id)
			return rateclass;
	}

	return NULL;
}

/* Subtype 0x0007 - Rate Parameters */
static int
rateresp(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	guint16 numclasses, i;
	aim_rxcallback_t userfunc;

	/*
	 * First are the parameters for each rate class.
	 */
	numclasses = byte_stream_get16(bs);
	for (i = 0; i < numclasses; i++)
	{
		struct rateclass *rateclass;
		guint32 delta;
		struct timeval now;

		gettimeofday(&now, NULL);
		rateclass = g_new(struct rateclass, 1);

		rateclass->classid = byte_stream_get16(bs);
		rateclass->windowsize = byte_stream_get32(bs);
		rateclass->clear = byte_stream_get32(bs);
		rateclass->alert = byte_stream_get32(bs);
		rateclass->limit = byte_stream_get32(bs);
		rateclass->disconnect = byte_stream_get32(bs);
		rateclass->current = byte_stream_get32(bs);
		rateclass->max = byte_stream_get32(bs);
		if (mod->version >= 3) {
			delta = byte_stream_get32(bs);
			rateclass->dropping_snacs = byte_stream_get8(bs);
		} else {
			delta = 0;
			rateclass->dropping_snacs = 0;
		}

		rateclass->last.tv_sec = now.tv_sec - delta / 1000;
		rateclass->last.tv_usec = now.tv_usec - (delta % 1000) * 1000;

		conn->rateclasses = g_slist_prepend(conn->rateclasses, rateclass);

		if (rateclass->classid == OSCAR_DEFAULT_RATECLASS)
			conn->default_rateclass = rateclass;
	}
	conn->rateclasses = g_slist_reverse(conn->rateclasses);

	/*
	 * Then the members of each class.
	 */
	for (i = 0; i < numclasses; i++)
	{
		guint16 classid, count;
		struct rateclass *rateclass;
		int j;

		classid = byte_stream_get16(bs);
		count = byte_stream_get16(bs);

		if (classid == OSCAR_DEFAULT_RATECLASS) {
			/*
			 * Don't bother adding these SNACs to the hash table.  See the
			 * comment for OSCAR_DEFAULT_RATECLASS at the top of this file.
			 */
			byte_stream_advance(bs, 4 * count);
			continue;
		}

		rateclass = rateclass_find(conn->rateclasses, classid);

		for (j = 0; j < count; j++)
		{
			guint16 group, subtype;

			group = byte_stream_get16(bs);
			subtype = byte_stream_get16(bs);

			if (rateclass != NULL)
				g_hash_table_insert(conn->rateclass_members,
						GUINT_TO_POINTER((group << 16) + subtype),
						rateclass);
		}
	}

	/*
	 * We don't pass the rate information up to the client, as it really
	 * doesn't care.  The information is stored in the connection, however
	 * so that we can do rate limiting management when sending SNACs.
	 */

	/*
	 * Subscribe to rate change information for all rate classes.
	 */
	aim_srv_rates_addparam(od, conn);

	/*
	 * Finally, tell the client it's ready to go...
	 */
	if ((userfunc = aim_callhandler(od, AIM_CB_FAM_SPECIAL, AIM_CB_SPECIAL_CONNINITDONE)))
		userfunc(od, conn, frame);

	return 1;
}

/* Subtype 0x0008 - Add Rate Parameter */
void
aim_srv_rates_addparam(OscarData *od, FlapConnection *conn)
{
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tmp;

	byte_stream_new(&bs, 502);

	for (tmp = conn->rateclasses; tmp != NULL; tmp = tmp->next)
	{
		struct rateclass *rateclass;
		rateclass = tmp->data;
		byte_stream_put16(&bs, rateclass->classid);
	}

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0008, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0008, snacid, &bs);

	byte_stream_destroy(&bs);
}

/* Subtype 0x000a - Rate Change */
static int
ratechange(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	guint16 code, classid;
	struct rateclass *rateclass;
	guint32 delta;
	struct timeval now;
	static const char *codes[5] = {
		"invalid",
		"change",
		"warning",
		"limit",
		"limit cleared",
	};

	gettimeofday(&now, NULL);
	code = byte_stream_get16(bs);
	classid = byte_stream_get16(bs);

	rateclass = rateclass_find(conn->rateclasses, classid);
	if (rateclass == NULL)
		/* This should never really happen */
		return 0;

	rateclass->windowsize = byte_stream_get32(bs);
	rateclass->clear = byte_stream_get32(bs);
	rateclass->alert = byte_stream_get32(bs);
	rateclass->limit = byte_stream_get32(bs);
	rateclass->disconnect = byte_stream_get32(bs);
	rateclass->current = byte_stream_get32(bs);
	rateclass->max = byte_stream_get32(bs);
	if (mod->version >= 3) {
		delta = byte_stream_get32(bs);
		rateclass->dropping_snacs = byte_stream_get8(bs);
	} else {
		delta = 0;
		rateclass->dropping_snacs = 0;
	}

	rateclass->last.tv_sec = now.tv_sec - delta / 1000;
	rateclass->last.tv_usec = now.tv_usec - (delta % 1000) * 1000;

	purple_debug_misc("oscar", "rate %s (param ID 0x%04hx): curavg = %u, "
			"maxavg = %u, alert at %u, clear warning at %u, limit at %u, "
			"disconnect at %u, delta is %u, dropping is %u (window size = %u)\n",
			(code < 5) ? codes[code] : codes[0], rateclass->classid,
			rateclass->current, rateclass->max, rateclass->alert,
			rateclass->clear, rateclass->limit, rateclass->disconnect,
			delta, rateclass->dropping_snacs, rateclass->windowsize);

	if (code == AIM_RATE_CODE_LIMIT) {
		purple_debug_warning("oscar",  "The last action you attempted "
				"could not be performed because you are over the rate "
				"limit. Please wait 10 seconds and try again.\n");
	}

	return 1;
}

/*
 * How Migrations work.
 *
 * The server sends a Server Pause message, which the client should respond to
 * with a Server Pause Ack, which contains the families it needs on this
 * connection. The server will send a Migration Notice with an IP address, and
 * then disconnect. Next the client should open the connection and send the
 * cookie.  Repeat the normal login process and pretend this never happened.
 *
 * The Server Pause contains no data.
 *
 */

/* Subtype 0x000b - Service Pause */
static int
serverpause(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame);

	return ret;
}

/* Subtype 0x000d - Service Resume */
static int
serverresume(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame);

	return ret;
}

/* Subtype 0x000e - Request self-info */
void
aim_srv_reqpersonalinfo(OscarData *od, FlapConnection *conn)
{
	aim_genericreq_n_snacid(od, conn, SNAC_FAMILY_OSERVICE, 0x000e);
}

/* Subtype 0x000f - Self User Info */
static int
selfinfo(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	aim_userinfo_t userinfo;

	aim_info_extract(od, bs, &userinfo);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, &userinfo);

	aim_info_free(&userinfo);

	return ret;
}

/* Subtype 0x0010 - Evil Notification */
static int
evilnotify(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint16 newevil;
	aim_userinfo_t userinfo;

	memset(&userinfo, 0, sizeof(aim_userinfo_t));

	newevil = byte_stream_get16(bs);

	if (byte_stream_bytes_left(bs))
		aim_info_extract(od, bs, &userinfo);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, newevil, &userinfo);

	aim_info_free(&userinfo);

	return ret;
}

/*
 * Subtype 0x0011 - Idle Notification
 *
 * Should set your current idle time in seconds.  Note that this should
 * never be called consecutively with a non-zero idle time.  That makes
 * OSCAR do funny things.  Instead, just set it once you go idle, and then
 * call it again with zero when you're back.
 *
 */
void
aim_srv_setidle(OscarData *od, guint32 idletime)
{
	FlapConnection *conn;

	conn = flap_connection_findbygroup(od, SNAC_FAMILY_BOS);
	if(!conn)
		return;

	aim_genericreq_l(od, conn, SNAC_FAMILY_OSERVICE, 0x0011, &idletime);
}

/*
 * Subtype 0x0012 - Service Migrate
 *
 * This is the final SNAC sent on the original connection during a migration.
 * It contains the IP and cookie used to connect to the new server, and
 * optionally a list of the SNAC groups being migrated.
 *
 */
static int
migrate(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	int ret = 0;
	guint16 groupcount, i;
	GSList *tlvlist;
	char *ip = NULL;
	aim_tlv_t *cktlv;

	/*
	 * Apparently there's some fun stuff that can happen right here. The
	 * migration can actually be quite selective about what groups it
	 * moves to the new server.  When not all the groups for a connection
	 * are migrated, or they are all migrated but some groups are moved
	 * to a different server than others, it is called a bifurcated
	 * migration.
	 *
	 * Let's play dumb and not support that.
	 *
	 */
	groupcount = byte_stream_get16(bs);
	for (i = 0; i < groupcount; i++) {
		guint16 group;

		group = byte_stream_get16(bs);

		purple_debug_misc("oscar", "bifurcated migration unsupported -- group 0x%04x\n", group);
	}

	tlvlist = aim_tlvlist_read(bs);

	if (aim_tlv_gettlv(tlvlist, 0x0005, 1))
		ip = aim_tlv_getstr(tlvlist, 0x0005, 1);

	cktlv = aim_tlv_gettlv(tlvlist, 0x0006, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, ip, cktlv ? cktlv->value : NULL);

	aim_tlvlist_free(tlvlist);
	g_free(ip);

	return ret;
}

/* Subtype 0x0013 - Message of the Day */
static int
motd(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	aim_rxcallback_t userfunc;
	char *msg = NULL;
	int ret = 0;
	GSList *tlvlist;
	guint16 id;

	/*
	 * Code.
	 *
	 * Valid values:
	 *   1 Mandatory upgrade
	 *   2 Advisory upgrade
	 *   3 System bulletin
	 *   4 Nothing's wrong ("top o the world" -- normal)
	 *   5 Lets-break-something.
	 *
	 */
	id = byte_stream_get16(bs);

	/*
	 * TLVs follow
	 */
	tlvlist = aim_tlvlist_read(bs);

	msg = aim_tlv_getstr(tlvlist, 0x000b, 1);

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, id, msg);

	g_free(msg);

	aim_tlvlist_free(tlvlist);

	return ret;
}

/*
 * Subtype 0x0017 - Set client versions
 *
 * If you've seen the clientonline/clientready SNAC you're probably
 * wondering what the point of this one is.  And that point seems to be
 * that the versions in the client online SNAC are sent too late for the
 * server to be able to use them to change the protocol for the earlier
 * login packets (client versions are sent right after Host Online is
 * received, but client online versions aren't sent until quite a bit later).
 * We can see them already making use of this by changing the format of
 * the rate information based on what version of group 1 we advertise here.
 *
 */
void
aim_srv_setversions(OscarData *od, FlapConnection *conn)
{
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *cur;

	byte_stream_new(&bs, 1142);

	/*
	 * Send only the versions that the server cares about (that it
	 * marked as supporting in the server ready SNAC).
	 */
	for (cur = conn->groups; cur != NULL; cur = cur->next)
	{
		aim_module_t *mod;

		if ((mod = aim__findmodulebygroup(od, GPOINTER_TO_UINT(cur->data))))
		{
			byte_stream_put16(&bs, mod->family);
			byte_stream_put16(&bs, mod->version);
		}
	}

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0017, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0017, snacid, &bs);

	byte_stream_destroy(&bs);
}

/* Subtype 0x0018 - Host versions */
static int
hostversions(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int vercount;
	guint8 *versions;

	/* This is frivolous. (Thank you SmarterChild.) */
	vercount = byte_stream_bytes_left(bs)/4;
	versions = byte_stream_getraw(bs, byte_stream_bytes_left(bs));
	g_free(versions);

	/*
	 * Now request rates.
	 */
	aim_srv_reqrates(od, conn);

	return 1;
}

/**
 * Subtype 0x001e - Extended Status/Extra Info.
 *
 * These settings are transient, not server-stored (i.e. they only
 * apply to this session, and must be re-set the next time you sign
 * on).
 *
 * You can set your ICQ status (available, away, do not disturb,
 * etc.), or whether your IP address should be hidden or not, or
 * if your status is visible on ICQ web sites, and you can set
 * your IP address info and what not.
 *
 * You can also set your "available" message.  This is currently
 * only supported by iChat, Purple and other 3rd party clients.
 *
 * These are the same TLVs seen in user info.  You can
 * also set 0x0008 and 0x000c.
 */
int
aim_srv_setextrainfo(OscarData *od,
		gboolean seticqstatus, guint32 icqstatus,
		gboolean setstatusmsg, const char *statusmsg, const char *itmsurl)
{
	FlapConnection *conn;
	ByteStream bs;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	if (!od || !(conn = flap_connection_findbygroup(od, SNAC_FAMILY_ICBM)))
		return -EINVAL;

	if (seticqstatus)
	{
		aim_tlvlist_add_32(&tlvlist, 0x0006, icqstatus |
				AIM_ICQ_STATE_HIDEIP | AIM_ICQ_STATE_DIRECTREQUIREAUTH);
	}

	if (setstatusmsg)
	{
		size_t statusmsglen, itmsurllen;
		ByteStream tmpbs;

		statusmsglen = (statusmsg != NULL) ? strlen(statusmsg) : 0;
		itmsurllen = (itmsurl != NULL) ? strlen(itmsurl) : 0;

		byte_stream_new(&tmpbs, statusmsglen + 8 + itmsurllen + 8);
		byte_stream_put_bart_asset_str(&tmpbs, 0x0002, statusmsg);
		byte_stream_put_bart_asset_str(&tmpbs, 0x0009, itmsurl);

		aim_tlvlist_add_raw(&tlvlist, 0x001d,
				byte_stream_curpos(&tmpbs), tmpbs.data);
		byte_stream_destroy(&tmpbs);
	}

	byte_stream_new(&bs, aim_tlvlist_size(tlvlist));

	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x001e, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x001e, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/* Send dummy DC (direct connect) information to the server.
 * Direct connect is ICQ's counterpart for AIM's DirectIM,
 * as far as I can tell. Anyway, we don't support it;
 * the reason to send this packet is that some clients
 * (Miranda, QIP) won't send us channel 2 ICBM messages
 * unless we specify DC version >= 8.
 *
 * See #12044 for more information.
 */
void
aim_srv_set_dc_info(OscarData *od)
{
	ByteStream bs, tlv0c;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	/* http://iserverd.khstu.ru/oscar/snac_01_1e.html has a nice analysis of what goes in 0xc tlv.
	 * Kopete sends a dummy DC info, too, so I just copied the values from them.
	 */
	byte_stream_new(&tlv0c, 4*2 + 1 + 2 + 4*6 + 2);
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put8(&tlv0c, 0x0); /* We don't support DC */
	byte_stream_put16(&tlv0c, 8); /* DC version */
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put32(&tlv0c, 0x50);
	byte_stream_put32(&tlv0c, 0x3);
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put32(&tlv0c, 0x0);
	byte_stream_put16(&tlv0c, 0x0);
	aim_tlvlist_add_raw(&tlvlist, 0x000c, byte_stream_curpos(&tlv0c), tlv0c.data);
	byte_stream_destroy(&tlv0c);

	byte_stream_new(&bs, aim_tlvlist_size(tlvlist));
	aim_tlvlist_write(&bs, &tlvlist);
	aim_tlvlist_free(tlvlist);

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x001e, 0x0000, NULL, 0);
	flap_connection_send_snac(od, flap_connection_findbygroup(od, SNAC_FAMILY_ICBM), SNAC_FAMILY_OSERVICE, 0x001e, snacid, &bs);

	byte_stream_destroy(&bs);
}

/**
 * Starting this past week (26 Mar 2001, say), AOL has started sending
 * this nice little extra SNAC.  AFAIK, it has never been used until now.
 *
 * The request contains eight bytes.  The first four are an offset, the
 * second four are a length.
 *
 * The offset is an offset into aim.exe when it is mapped during execution
 * on Win32.  So far, AOL has only been requesting bytes in static regions
 * of memory.  (I won't put it past them to start requesting data in
 * less static regions -- regions that are initialized at run time, but still
 * before the client receives this request.)
 *
 * When the client receives the request, it adds it to the current ds
 * (0x00400000) and dereferences it, copying the data into a buffer which
 * it then runs directly through the MD5 hasher.  The 16 byte output of
 * the hash is then sent back to the server.
 *
 * If the client does not send any data back, or the data does not match
 * the data that the specific client should have, the client will get the
 * following message from "AOL Instant Messenger":
 *    "You have been disconnected from the AOL Instant Message Service (SM)
 *     for accessing the AOL network using unauthorized software.  You can
 *     download a FREE, fully featured, and authorized client, here
 *     http://www.aol.com/aim/download2.html"
 * The connection is then closed, receiving disconnect code 1, URL
 * http://www.aim.aol.com/errors/USER_LOGGED_OFF_NEW_LOGIN.html.
 *
 * Note, however, that numerous inconsistencies can cause the above error,
 * not just sending back a bad hash.  Do not immediatly suspect this code
 * if you get disconnected.  AOL and the open/free software community have
 * played this game for a couple years now, generating the above message
 * on numerous ocassions.
 *
 * Anyway, neener.  We win again.
 *
 */
/* Subtype 0x001f - Client verification */
static int
memrequest(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint32 offset, len;
	GSList *tlvlist;
	char *modname;

	offset = byte_stream_get32(bs);
	len = byte_stream_get32(bs);
	tlvlist = aim_tlvlist_read(bs);

	modname = aim_tlv_getstr(tlvlist, 0x0001, 1);

	purple_debug_info("oscar", "Got memory request for data at 0x%08x (%u bytes) of requested %s\n", offset, len, modname ? modname : "aim.exe");

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, offset, len, modname);

	g_free(modname);
	aim_tlvlist_free(tlvlist);

	return ret;
}

/* Subtype 0x0020 - Client verification reply */
int
aim_sendmemblock(OscarData *od, FlapConnection *conn, guint32 offset, guint32 len, const guint8 *buf, guint8 flag)
{
	ByteStream bs;
	aim_snacid_t snacid;

	if (!od || !conn)
		return -EINVAL;

	byte_stream_new(&bs, 2+16);

	byte_stream_put16(&bs, 0x0010); /* md5 is always 16 bytes */

	if ((flag == AIM_SENDMEMBLOCK_FLAG_ISHASH) && buf && (len == 0x10)) { /* we're getting a hash */

		byte_stream_putraw(&bs, buf, 0x10);

	} else if (buf && (len > 0)) { /* use input buffer */
		PurpleCipherContext *context;
		guchar digest[16];

		context = purple_cipher_context_new_by_name("md5", NULL);
		purple_cipher_context_append(context, buf, len);
		purple_cipher_context_digest(context, 16, digest, NULL);
		purple_cipher_context_destroy(context);

		byte_stream_putraw(&bs, digest, 0x10);

	} else if (len == 0) { /* no length, just hash NULL (buf is optional) */
		PurpleCipherContext *context;
		guchar digest[16];
		guint8 nil = '\0';

		/*
		 * I'm not sure if we really need the empty append with the
		 * new MD5 functions, so I'll leave it in, just in case.
		 */
		context = purple_cipher_context_new_by_name("md5", NULL);
		purple_cipher_context_append(context, &nil, 0);
		purple_cipher_context_digest(context, 16, digest, NULL);
		purple_cipher_context_destroy(context);

		byte_stream_putraw(&bs, digest, 0x10);

	} else {

		/*
		 * This data is correct for AIM 3.5.1670.
		 *
		 * Using these blocks is as close to "legal" as you can get
		 * without using an AIM binary.
		 *
		 */
		if ((offset == 0x03ffffff) && (len == 0x03ffffff)) {

#if 1 /* with "AnrbnrAqhfzcd" */
			byte_stream_put32(&bs, 0x44a95d26);
			byte_stream_put32(&bs, 0xd2490423);
			byte_stream_put32(&bs, 0x93b8821f);
			byte_stream_put32(&bs, 0x51c54b01);
#else /* no filename */
			byte_stream_put32(&bs, 0x1df8cbae);
			byte_stream_put32(&bs, 0x5523b839);
			byte_stream_put32(&bs, 0xa0e10db3);
			byte_stream_put32(&bs, 0xa46d3b39);
#endif

		} else
			purple_debug_warning("oscar", "sendmemblock: unknown hash request\n");

	}

	snacid = aim_cachesnac(od, SNAC_FAMILY_OSERVICE, 0x0020, 0x0000, NULL, 0);
	flap_connection_send_snac(od, conn, SNAC_FAMILY_OSERVICE, 0x0020, snacid, &bs);

	byte_stream_destroy(&bs);

	return 0;
}

/*
 * Subtype 0x0021 - Receive our extended status
 *
 * This is used for iChat's "available" messages, and maybe ICQ extended
 * status messages?  It's also used to tell the client whether or not it
 * needs to upload an SSI buddy icon... who engineers this stuff, anyway?
 */
static int
aim_parse_extstatus(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	guint16 type = byte_stream_get16(bs);
	if (type == 0x0000 || type == 0x0001) {
		/* buddy icon checksum */
		/* not sure what the difference between 1 and 0 is */
		guint8 flags = byte_stream_get8(bs);
		guint8 length = byte_stream_get8(bs);
		guint8 *md5 = byte_stream_getraw(bs, length);

		if ((flags == 0x00) || (flags == 0x41)) {
			if (!flap_connection_getbytype(od, SNAC_FAMILY_BART) && !od->iconconnecting) {
				od->iconconnecting = TRUE;
				od->set_icon = TRUE;
				aim_srv_requestnew(od, SNAC_FAMILY_BART);
			} else {
				PurpleAccount *account = purple_connection_get_account(od->gc);
				PurpleStoredImage *img = purple_buddy_icons_find_account_icon(account);
				if (img == NULL) {
					aim_ssi_delicon(od);
				} else {

					purple_debug_info("oscar",
									"Uploading icon to icon server\n");
					aim_bart_upload(od, purple_imgstore_get_data(img),
							purple_imgstore_get_size(img));
					purple_imgstore_unref(img);
				}
			}
		} else if (flags == 0x81) {
			PurpleAccount *account = purple_connection_get_account(od->gc);
			PurpleStoredImage *img = purple_buddy_icons_find_account_icon(account);
			if (img == NULL)
				aim_ssi_delicon(od);
			else {
				aim_ssi_seticon(od, md5, length);
				purple_imgstore_unref(img);
			}
		}

		g_free(md5);
	}

	return 0;
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0003)
		return hostonline(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0005)
		return redirect(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0007)
		return rateresp(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000a)
		return ratechange(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000b)
		return serverpause(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000d)
		return serverresume(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000f)
		return selfinfo(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0010)
		return evilnotify(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0012)
		return migrate(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0013)
		return motd(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0018)
		return hostversions(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x001f)
		return memrequest(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0021)
		return aim_parse_extstatus(od, conn, mod, frame, snac, bs);

	return 0;
}

int service_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_OSERVICE;
	mod->version = 0x0003;
	mod->toolid = 0x0110;
	mod->toolversion = 0x0629;
	mod->flags = 0;
	strncpy(mod->name, "oservice", sizeof(mod->name));
	mod->snachandler = snachandler;

	return 0;
}
