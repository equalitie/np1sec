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
 * Family 0x0017 - Authentication.
 *
 * Deals with the authorizer for SNAC-based login, and also old-style
 * non-SNAC login.
 *
 */

#include "oscar.h"

#include <ctype.h>

#include "cipher.h"

/* #define USE_XOR_FOR_ICQ */

#ifdef USE_XOR_FOR_ICQ
/**
 * Encode a password using old XOR method
 *
 * This takes a const pointer to a (null terminated) string
 * containing the unencoded password.  It also gets passed
 * an already allocated buffer to store the encoded password.
 * This buffer should be the exact length of the password without
 * the null.  The encoded password buffer /is not %NULL terminated/.
 *
 * The encoding_table seems to be a fixed set of values.  We'll
 * hope it doesn't change over time!
 *
 * This is only used for the XOR method, not the better MD5 method.
 *
 * @param password Incoming password.
 * @param encoded Buffer to put encoded password.
 */
static int
aim_encode_password(const char *password, guint8 *encoded)
{
	guint8 encoding_table[] = {
		0xf3, 0x26, 0x81, 0xc4,
		0x39, 0x86, 0xdb, 0x92,
		0x71, 0xa3, 0xb9, 0xe6,
		0x53, 0x7a, 0x95, 0x7c
	};
	unsigned int i;

	for (i = 0; i < strlen(password); i++)
		encoded[i] = (password[i] ^ encoding_table[i]);

	return 0;
}
#endif

#ifdef USE_OLD_MD5
static int
aim_encode_password_md5(const char *password, size_t password_len, const char *key, guint8 *digest)
{
	PurpleCipherContext *context;

	context = purple_cipher_context_new_by_name("md5", NULL);
	purple_cipher_context_append(context, (const guchar *)key, strlen(key));
	purple_cipher_context_append(context, (const guchar *)password, password_len);
	purple_cipher_context_append(context, (const guchar *)AIM_MD5_STRING, strlen(AIM_MD5_STRING));
	purple_cipher_context_digest(context, 16, digest, NULL);
	purple_cipher_context_destroy(context);

	return 0;
}
#else
static int
aim_encode_password_md5(const char *password, size_t password_len, const char *key, guint8 *digest)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	guchar passdigest[16];

	cipher = purple_ciphers_find_cipher("md5");

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (const guchar *)password, password_len);
	purple_cipher_context_digest(context, 16, passdigest, NULL);
	purple_cipher_context_destroy(context);

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (const guchar *)key, strlen(key));
	purple_cipher_context_append(context, passdigest, 16);
	purple_cipher_context_append(context, (const guchar *)AIM_MD5_STRING, strlen(AIM_MD5_STRING));
	purple_cipher_context_digest(context, 16, digest, NULL);
	purple_cipher_context_destroy(context);

	return 0;
}
#endif

#ifdef USE_XOR_FOR_ICQ
/*
 * Part two of the ICQ hack.  Note the ignoring of the key.
 */
static int
goddamnicq2(OscarData *od, FlapConnection *conn, const char *sn, const char *password, ClientInfo *ci)
{
	FlapFrame *frame;
	GSList *tlvlist = NULL;
	int passwdlen;
	guint8 *password_encoded;
	guint32 distrib;

	passwdlen = strlen(password);
	password_encoded = (guint8 *)g_malloc(passwdlen+1);
	if (passwdlen > MAXICQPASSLEN)
		passwdlen = MAXICQPASSLEN;

	frame = flap_frame_new(od, 0x01, 1152);

	aim_encode_password(password, password_encoded);

	distrib = oscar_get_ui_info_int(
			od->icq ? "prpl-icq-distid" : "prpl-aim-distid",
			ci->distrib);

	byte_stream_put32(&frame->data, 0x00000001); /* FLAP Version */
	aim_tlvlist_add_str(&tlvlist, 0x0001, sn);
	aim_tlvlist_add_raw(&tlvlist, 0x0002, passwdlen, password_encoded);

	if (ci->clientstring != NULL)
		aim_tlvlist_add_str(&tlvlist, 0x0003, ci->clientstring);
	else {
		gchar *clientstring = oscar_get_clientstring();
		aim_tlvlist_add_str(&tlvlist, 0x0003, clientstring);
		g_free(clientstring);
	}
	aim_tlvlist_add_16(&tlvlist, 0x0016, (guint16)ci->clientid);
	aim_tlvlist_add_16(&tlvlist, 0x0017, (guint16)ci->major);
	aim_tlvlist_add_16(&tlvlist, 0x0018, (guint16)ci->minor);
	aim_tlvlist_add_16(&tlvlist, 0x0019, (guint16)ci->point);
	aim_tlvlist_add_16(&tlvlist, 0x001a, (guint16)ci->build);
	aim_tlvlist_add_32(&tlvlist, 0x0014, distrib); /* distribution chan */
	aim_tlvlist_add_str(&tlvlist, 0x000f, ci->lang);
	aim_tlvlist_add_str(&tlvlist, 0x000e, ci->country);

	aim_tlvlist_write(&frame->data, &tlvlist);

	g_free(password_encoded);
	aim_tlvlist_free(tlvlist);

	flap_connection_send(conn, frame);

	return 0;
}
#endif

/*
 * Subtype 0x0002
 *
 * This is the initial login request packet.
 *
 * NOTE!! If you want/need to make use of the aim_sendmemblock() function,
 * then the client information you send here must exactly match the
 * executable that you're pulling the data from.
 *
 * Java AIM 1.1.19:
 *   clientstring = "AOL Instant Messenger (TM) version 1.1.19 for Java built 03/24/98, freeMem 215871 totalMem 1048567, i686, Linus, #2 SMP Sun Feb 11 03:41:17 UTC 2001 2.4.1-ac9, IBM Corporation, 1.1.8, 45.3, Tue Mar 27 12:09:17 PST 2001"
 *   clientid = 0x0001
 *   major  = 0x0001
 *   minor  = 0x0001
 *   point = (not sent)
 *   build  = 0x0013
 *   unknown= (not sent)
 *
 * AIM for Linux 1.1.112:
 *   clientstring = "AOL Instant Messenger (SM)"
 *   clientid = 0x1d09
 *   major  = 0x0001
 *   minor  = 0x0001
 *   point = 0x0001
 *   build  = 0x0070
 *   unknown= 0x0000008b
 *   serverstore = 0x01
 *
 * @param truncate_pass Truncate the password to 8 characters.  This
 *        usually happens for AOL accounts.  We are told that we
 *        should truncate it if the 0x0017/0x0007 SNAC contains
 *        a TLV of type 0x0026 with data 0x0000.
 * @param allow_multiple_logins Allow multiple logins? If TRUE, the AIM
 *        server will prompt the user when multiple logins occur. If
 *        FALSE, existing connections (on other clients) will be
 *        disconnected automatically as we connect.
 */
int
aim_send_login(OscarData *od, FlapConnection *conn, const char *sn, const char *password, gboolean truncate_pass, ClientInfo *ci, const char *key, gboolean allow_multiple_logins)
{
	FlapFrame *frame;
	GSList *tlvlist = NULL;
	guint8 digest[16];
	aim_snacid_t snacid;
	size_t password_len;
	guint32 distrib;

	if (!ci || !sn || !password)
		return -EINVAL;

#ifdef USE_XOR_FOR_ICQ
	/* If we're signing on an ICQ account then use the older, XOR login method */
	if (aim_snvalid_icq(sn))
		return goddamnicq2(od, conn, sn, password, ci);
#endif

	frame = flap_frame_new(od, 0x02, 1152);

	snacid = aim_cachesnac(od, SNAC_FAMILY_AUTH, 0x0002, 0x0000, NULL, 0);
	aim_putsnac(&frame->data, SNAC_FAMILY_AUTH, 0x0002, snacid);

	aim_tlvlist_add_str(&tlvlist, 0x0001, sn);

	/* Truncate ICQ and AOL passwords, if necessary */
	password_len = strlen(password);
	if (oscar_util_valid_name_icq(sn) && (password_len > MAXICQPASSLEN))
		password_len = MAXICQPASSLEN;
	else if (truncate_pass && password_len > 8)
		password_len = 8;

	aim_encode_password_md5(password, password_len, key, digest);

	distrib = oscar_get_ui_info_int(
			od->icq ? "prpl-icq-distid" : "prpl-aim-distid",
			ci->distrib);

	aim_tlvlist_add_raw(&tlvlist, 0x0025, 16, digest);

#ifndef USE_OLD_MD5
	aim_tlvlist_add_noval(&tlvlist, 0x004c);
#endif

	if (ci->clientstring != NULL)
		aim_tlvlist_add_str(&tlvlist, 0x0003, ci->clientstring);
	else {
		gchar *clientstring = oscar_get_clientstring();
		aim_tlvlist_add_str(&tlvlist, 0x0003, clientstring);
		g_free(clientstring);
	}
	aim_tlvlist_add_16(&tlvlist, 0x0016, (guint16)ci->clientid);
	aim_tlvlist_add_16(&tlvlist, 0x0017, (guint16)ci->major);
	aim_tlvlist_add_16(&tlvlist, 0x0018, (guint16)ci->minor);
	aim_tlvlist_add_16(&tlvlist, 0x0019, (guint16)ci->point);
	aim_tlvlist_add_16(&tlvlist, 0x001a, (guint16)ci->build);
	aim_tlvlist_add_32(&tlvlist, 0x0014, distrib);
	aim_tlvlist_add_str(&tlvlist, 0x000f, ci->lang);
	aim_tlvlist_add_str(&tlvlist, 0x000e, ci->country);

	/*
	 * If set, old-fashioned buddy lists will not work. You will need
	 * to use SSI.
	 */
	aim_tlvlist_add_8(&tlvlist, 0x004a, (allow_multiple_logins ? 0x01 : 0x03));

	aim_tlvlist_write(&frame->data, &tlvlist);

	aim_tlvlist_free(tlvlist);

	flap_connection_send(conn, frame);

	return 0;
}

/*
 * This is sent back as a general response to the login command.
 * It can be either an error or a success, depending on the
 * presence of certain TLVs.
 *
 * The client should check the value passed as errorcode. If
 * its nonzero, there was an error.
 */
static int
parse(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	GSList *tlvlist;
	aim_rxcallback_t userfunc;
	struct aim_authresp_info *info;
	int ret = 0;

	info = g_new0(struct aim_authresp_info, 1);

	/*
	 * Read block of TLVs.  All further data is derived
	 * from what is parsed here.
	 */
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * No matter what, we should have a username.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0001, 1)) {
		info->bn = aim_tlv_getstr(tlvlist, 0x0001, 1);
		purple_connection_set_display_name(od->gc, info->bn);
	}

	/*
	 * Check for an error code.  If so, we should also
	 * have an error url.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0008, 1))
		info->errorcode = aim_tlv_get16(tlvlist, 0x0008, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0004, 1))
		info->errorurl = aim_tlv_getstr(tlvlist, 0x0004, 1);

	/*
	 * BOS server address.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0005, 1))
		info->bosip = aim_tlv_getstr(tlvlist, 0x0005, 1);

	/*
	 * Authorization cookie.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0006, 1)) {
		aim_tlv_t *tmptlv;

		tmptlv = aim_tlv_gettlv(tlvlist, 0x0006, 1);
		if (tmptlv != NULL)
		{
			info->cookielen = tmptlv->length;
			info->cookie = tmptlv->value;
		}
	}

	/*
	 * The email address attached to this account
	 *   Not available for ICQ or @mac.com logins.
	 *   If you receive this TLV, then you are allowed to use
	 *   family 0x0018 to check the status of your email.
	 * XXX - Not really true!
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0011, 1))
		info->email = aim_tlv_getstr(tlvlist, 0x0011, 1);

	/*
	 * The registration status.  (Not real sure what it means.)
	 *   Not available for ICQ or @mac.com logins.
	 *
	 *   1 = No disclosure
	 *   2 = Limited disclosure
	 *   3 = Full disclosure
	 *
	 * This has to do with whether your email address is available
	 * to other users or not.  AFAIK, this feature is no longer used.
	 *
	 * Means you can use the admin family? (0x0007)
	 *
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0013, 1))
		info->regstatus = aim_tlv_get16(tlvlist, 0x0013, 1);

	if (aim_tlv_gettlv(tlvlist, 0x0040, 1))
		info->latestbeta.build = aim_tlv_get32(tlvlist, 0x0040, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0041, 1))
		info->latestbeta.url = aim_tlv_getstr(tlvlist, 0x0041, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0042, 1))
		info->latestbeta.info = aim_tlv_getstr(tlvlist, 0x0042, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0043, 1))
		info->latestbeta.name = aim_tlv_getstr(tlvlist, 0x0043, 1);

	if (aim_tlv_gettlv(tlvlist, 0x0044, 1))
		info->latestrelease.build = aim_tlv_get32(tlvlist, 0x0044, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0045, 1))
		info->latestrelease.url = aim_tlv_getstr(tlvlist, 0x0045, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0046, 1))
		info->latestrelease.info = aim_tlv_getstr(tlvlist, 0x0046, 1);
	if (aim_tlv_gettlv(tlvlist, 0x0047, 1))
		info->latestrelease.name = aim_tlv_getstr(tlvlist, 0x0047, 1);

	/*
	 * URL to change password.
	 */
	if (aim_tlv_gettlv(tlvlist, 0x0054, 1))
		info->chpassurl = aim_tlv_getstr(tlvlist, 0x0054, 1);

	od->authinfo = info;

	if ((userfunc = aim_callhandler(od, snac ? snac->family : SNAC_FAMILY_AUTH, snac ? snac->subtype : 0x0003)))
		ret = userfunc(od, conn, frame, info);

	aim_tlvlist_free(tlvlist);

	return ret;
}

#ifdef USE_XOR_FOR_ICQ
/*
 * Subtype 0x0007 (kind of) - Send a fake type 0x0007 SNAC to the client
 *
 * This is a bit confusing.
 *
 * Normal SNAC login goes like this:
 *   - connect
 *   - server sends flap version
 *   - client sends flap version
 *   - client sends username (17/6)
 *   - server sends hash key (17/7)
 *   - client sends auth request (17/2 -- aim_send_login)
 *   - server yells
 *
 * XOR login (for ICQ) goes like this:
 *   - connect
 *   - server sends flap version
 *   - client sends auth request which contains flap version (aim_send_login)
 *   - server yells
 *
 * For the client API, we make them implement the most complicated version,
 * and for the simpler version, we fake it and make it look like the more
 * complicated process.
 *
 * This is done by giving the client a faked key, just so we can convince
 * them to call aim_send_login right away, which will detect the session
 * flag that says this is XOR login and ignore the key, sending an ICQ
 * login request instead of the normal SNAC one.
 *
 * As soon as AOL makes ICQ log in the same way as AIM, this is /gone/.
 */
static int
goddamnicq(OscarData *od, FlapConnection *conn, const char *sn)
{
	FlapFrame frame;
	aim_rxcallback_t userfunc;

	if ((userfunc = aim_callhandler(od, SNAC_FAMILY_AUTH, 0x0007)))
		userfunc(od, conn, &frame, "");

	return 0;
}
#endif

/*
 * Subtype 0x0006
 *
 * In AIM 3.5 protocol, the first stage of login is to request login from the
 * Authorizer, passing it the username for verification.  If the name is
 * invalid, a 0017/0003 is spit back, with the standard error contents.  If
 * valid, a 0017/0007 comes back, which is the signal to send it the main
 * login command (0017/0002).
 *
 */
int
aim_request_login(OscarData *od, FlapConnection *conn, const char *sn)
{
	FlapFrame *frame;
	aim_snacid_t snacid;
	GSList *tlvlist = NULL;

	if (!od || !conn || !sn)
		return -EINVAL;

#ifdef USE_XOR_FOR_ICQ
	if (aim_snvalid_icq(sn))
		return goddamnicq(od, conn, sn);
#endif

	frame = flap_frame_new(od, 0x02, 10+2+2+strlen(sn)+8);

	snacid = aim_cachesnac(od, SNAC_FAMILY_AUTH, 0x0006, 0x0000, NULL, 0);
	aim_putsnac(&frame->data, SNAC_FAMILY_AUTH, 0x0006, snacid);

	aim_tlvlist_add_str(&tlvlist, 0x0001, sn);

	/* Tell the server we support SecurID logins. */
	aim_tlvlist_add_noval(&tlvlist, 0x004b);

	/* Unknown.  Sent in recent WinAIM clients.*/
	aim_tlvlist_add_noval(&tlvlist, 0x005a);

	aim_tlvlist_write(&frame->data, &tlvlist);
	aim_tlvlist_free(tlvlist);

	flap_connection_send(conn, frame);

	return 0;
}

/*
 * Subtype 0x0007
 *
 * Middle handler for 0017/0007 SNACs.  Contains the auth key prefixed
 * by only its length in a two byte word.
 *
 * Calls the client, which should then use the value to call aim_send_login.
 *
 */
static int
keyparse(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int keylen, ret = 1;
	aim_rxcallback_t userfunc;
	char *keystr;
	GSList *tlvlist;
	gboolean truncate_pass;

	keylen = byte_stream_get16(bs);
	keystr = byte_stream_getstr(bs, keylen);
	tlvlist = aim_tlvlist_read(bs);

	/*
	 * If the truncate_pass TLV exists then we should truncate the
	 * user's password to 8 characters.  This flag is sent to us
	 * when logging in with an AOL user's username.
	 */
	truncate_pass = aim_tlv_gettlv(tlvlist, 0x0026, 1) != NULL;

	/* XXX - When GiantGrayPanda signed on AIM I got a thing asking me to register
	 * for the netscape network.  This SNAC had a type 0x0058 TLV with length 10.
	 * Data is 0x0007 0004 3e19 ae1e 0006 0004 0000 0005 */

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame, keystr, (int)truncate_pass);

	g_free(keystr);
	aim_tlvlist_free(tlvlist);

	return ret;
}

/**
 * Subtype 0x000a
 *
 * Receive SecurID request.
 */
static int
got_securid_request(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	int ret = 0;
	aim_rxcallback_t userfunc;

	if ((userfunc = aim_callhandler(od, snac->family, snac->subtype)))
		ret = userfunc(od, conn, frame);

	return ret;
}

/**
 * Subtype 0x000b
 *
 * Send SecurID response.
 */
int
aim_auth_securid_send(OscarData *od, const char *securid)
{
	FlapConnection *conn;
	FlapFrame *frame;
	aim_snacid_t snacid;
	int len;

	if (!od || !(conn = flap_connection_getbytype_all(od, SNAC_FAMILY_AUTH)) || !securid)
		return -EINVAL;

	len = strlen(securid);

	frame = flap_frame_new(od, 0x02, 10+2+len);

	snacid = aim_cachesnac(od, SNAC_FAMILY_AUTH, SNAC_SUBTYPE_AUTH_SECURID_RESPONSE, 0x0000, NULL, 0);
	aim_putsnac(&frame->data, SNAC_FAMILY_AUTH, SNAC_SUBTYPE_AUTH_SECURID_RESPONSE, 0);

	byte_stream_put16(&frame->data, len);
	byte_stream_putstr(&frame->data, securid);

	flap_connection_send(conn, frame);

	return 0;
}

static void
auth_shutdown(OscarData *od, aim_module_t *mod)
{
	if (od->authinfo != NULL)
	{
		g_free(od->authinfo->bn);
		g_free(od->authinfo->bosip);
		g_free(od->authinfo->errorurl);
		g_free(od->authinfo->email);
		g_free(od->authinfo->chpassurl);
		g_free(od->authinfo->latestrelease.name);
		g_free(od->authinfo->latestrelease.url);
		g_free(od->authinfo->latestrelease.info);
		g_free(od->authinfo->latestbeta.name);
		g_free(od->authinfo->latestbeta.url);
		g_free(od->authinfo->latestbeta.info);
		g_free(od->authinfo);
	}
}

static int
snachandler(OscarData *od, FlapConnection *conn, aim_module_t *mod, FlapFrame *frame, aim_modsnac_t *snac, ByteStream *bs)
{
	if (snac->subtype == 0x0003)
		return parse(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x0007)
		return keyparse(od, conn, mod, frame, snac, bs);
	else if (snac->subtype == 0x000a)
		return got_securid_request(od, conn, mod, frame, snac, bs);

	return 0;
}

int
auth_modfirst(OscarData *od, aim_module_t *mod)
{
	mod->family = SNAC_FAMILY_AUTH;
	mod->version = 0x0000;
	mod->flags = 0;
	strncpy(mod->name, "auth", sizeof(mod->name));
	mod->snachandler = snachandler;
	mod->shutdown = auth_shutdown;

	return 0;
}
