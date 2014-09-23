/*
 * purple - Jabber Protocol Plugin
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */
#include "internal.h"
#include "account.h"
#include "cipher.h"
#include "conversation.h"
#include "debug.h"
#include "server.h"
#include "util.h"
#include "xmlnode.h"

#include "chat.h"
#include "presence.h"
#include "jutil.h"

#ifdef USE_IDN
#include <idna.h>
#include <stringprep.h>
static char idn_buffer[1024];
#endif

#ifdef USE_IDN
static gboolean jabber_nodeprep(char *str, size_t buflen)
{
	return stringprep_xmpp_nodeprep(str, buflen) == STRINGPREP_OK;
}

static gboolean jabber_resourceprep(char *str, size_t buflen)
{
	return stringprep_xmpp_resourceprep(str, buflen) == STRINGPREP_OK;
}

static JabberID*
jabber_idn_validate(const char *str, const char *at, const char *slash,
                    const char *null)
{
	const char *node = NULL;
	const char *domain = NULL;
	const char *resource = NULL;
	int node_len = 0;
	int domain_len = 0;
	int resource_len = 0;
	char *out;
	JabberID *jid;

	/* Ensure no parts are > 1023 bytes */
	if (at) {
		node = str;
		node_len = at - str;

		domain = at + 1;
		if (slash) {
			domain_len = slash - (at + 1);
			resource = slash + 1;
			resource_len = null - (slash + 1);
		} else {
			domain_len = null - (at + 1);
		}
	} else {
		domain = str;

		if (slash) {
			domain_len = slash - str;
			resource = slash;
			resource_len = null - (slash + 1);
		} else {
			domain_len = null - (str + 1);
		}
	}

	if (node && node_len > 1023)
		return NULL;
	if (domain_len > 1023)
		return NULL;
	if (resource && resource_len > 1023)
		return NULL;

	jid = g_new0(JabberID, 1);

	if (node) {
		strncpy(idn_buffer, node, node_len);
		idn_buffer[node_len] = '\0';

		if (!jabber_nodeprep(idn_buffer, sizeof(idn_buffer))) {
			jabber_id_free(jid);
			jid = NULL;
			goto out;
		}

		jid->node = g_strdup(idn_buffer);
	}

	/* domain *must* be here */
	strncpy(idn_buffer, domain, domain_len);
	idn_buffer[domain_len] = '\0';
	if (domain[0] == '[') { /* IPv6 address */
		gboolean valid = FALSE;

		if (idn_buffer[domain_len - 1] == ']') {
			idn_buffer[domain_len - 1] = '\0';
			valid = purple_ipv6_address_is_valid(idn_buffer + 1);
		}

		if (!valid) {
			jabber_id_free(jid);
			jid = NULL;
			goto out;
		}
	} else {
		/* Apply nameprep */
		if (stringprep_nameprep(idn_buffer, sizeof(idn_buffer)) != STRINGPREP_OK) {
			jabber_id_free(jid);
			jid = NULL;
			goto out;
		}

		/* And now ToASCII */
		if (idna_to_ascii_8z(idn_buffer, &out, IDNA_USE_STD3_ASCII_RULES) != IDNA_SUCCESS) {
			jabber_id_free(jid);
			jid = NULL;
			goto out;
		}

		/* This *MUST* be freed using 'free', not 'g_free' */
		free(out);
		jid->domain = g_strdup(idn_buffer);
	}

	if (resource) {
		strncpy(idn_buffer, resource, resource_len);
		idn_buffer[resource_len] = '\0';

		if (!jabber_resourceprep(idn_buffer, sizeof(idn_buffer))) {
			jabber_id_free(jid);
			jid = NULL;
			goto out;
		} else
			jid->resource = g_strdup(idn_buffer);
	}

out:
	return jid;
}

#endif /* USE_IDN */

gboolean jabber_nodeprep_validate(const char *str)
{
#ifdef USE_IDN
	gboolean result;
#else
	const char *c;
#endif

	if(!str)
		return TRUE;

	if(strlen(str) > 1023)
		return FALSE;

#ifdef USE_IDN
	strncpy(idn_buffer, str, sizeof(idn_buffer) - 1);
	idn_buffer[sizeof(idn_buffer) - 1] = '\0';
	result = jabber_nodeprep(idn_buffer, sizeof(idn_buffer));
	return result;
#else /* USE_IDN */
	c = str;
	while(c && *c) {
		gunichar ch = g_utf8_get_char(c);
		if(ch == '\"' || ch == '&' || ch == '\'' || ch == '/' || ch == ':' ||
				ch == '<' || ch == '>' || ch == '@' || !g_unichar_isgraph(ch)) {
			return FALSE;
		}
		c = g_utf8_next_char(c);
	}

	return TRUE;
#endif /* USE_IDN */
}

gboolean jabber_domain_validate(const char *str)
{
	const char *c;
	size_t len;

	if(!str)
		return TRUE;

	len = strlen(str);
	if (len > 1023)
		return FALSE;

	c = str;

	if (*c == '[') {
		/* Check if str is a valid IPv6 identifier */
		gboolean valid = FALSE;

		if (*(c + len - 1) != ']')
			return FALSE;

		/* Ugly, but in-place */
		*(gchar *)(c + len - 1) = '\0';
		valid = purple_ipv6_address_is_valid(c + 1);
		*(gchar *)(c + len - 1) = ']';

		return valid;
	}

	while(c && *c) {
		gunichar ch = g_utf8_get_char(c);
		/* The list of characters allowed in domain names is pretty small */
		if ((ch <= 0x7F && !( (ch >= 'a' && ch <= 'z')
				|| (ch >= '0' && ch <= '9')
				|| (ch >= 'A' && ch <= 'Z')
				|| ch == '.'
				|| ch == '-' )) || (ch >= 0x80 && !g_unichar_isgraph(ch)))
			return FALSE;

		c = g_utf8_next_char(c);
	}

	return TRUE;
}

gboolean jabber_resourceprep_validate(const char *str)
{
#ifdef USE_IDN
	gboolean result;
#else
	const char *c;
#endif

	if(!str)
		return TRUE;

	if(strlen(str) > 1023)
		return FALSE;

#ifdef USE_IDN
	strncpy(idn_buffer, str, sizeof(idn_buffer) - 1);
	idn_buffer[sizeof(idn_buffer) - 1] = '\0';
	result = jabber_resourceprep(idn_buffer, sizeof(idn_buffer));
	return result;
#else /* USE_IDN */
	c = str;
	while(c && *c) {
		gunichar ch = g_utf8_get_char(c);
		if(!g_unichar_isgraph(ch) && ch != ' ')
			return FALSE;

		c = g_utf8_next_char(c);
	}

	return TRUE;
#endif /* USE_IDN */
}

char *jabber_saslprep(const char *in)
{
#ifdef USE_IDN
	char *out;

	g_return_val_if_fail(in != NULL, NULL);
	g_return_val_if_fail(strlen(in) <= sizeof(idn_buffer) - 1, NULL);

	strncpy(idn_buffer, in, sizeof(idn_buffer) - 1);
	idn_buffer[sizeof(idn_buffer) - 1] = '\0';

	if (STRINGPREP_OK != stringprep(idn_buffer, sizeof(idn_buffer), 0,
	                                stringprep_saslprep)) {
		memset(idn_buffer, 0, sizeof(idn_buffer));
		return NULL;
	}

	out = g_strdup(idn_buffer);
	memset(idn_buffer, 0, sizeof(idn_buffer));
	return out;
#else /* USE_IDN */
	/* TODO: Something better than disallowing all non-ASCII characters */
	/* TODO: Is this even correct? */
	const guchar *c;

	c = (const guchar *)in;
	for ( ; *c; ++c) {
		if (*c > 0x7f || /* Non-ASCII characters */
				*c == 0x7f || /* ASCII Delete character */
				(*c < 0x20 && *c != '\t' && *c != '\n' && *c != '\r'))
					/* ASCII control characters */
			return NULL;
	}

	return g_strdup(in);
#endif /* USE_IDN */
}

static JabberID*
jabber_id_new_internal(const char *str, gboolean allow_terminating_slash)
{
	const char *at = NULL;
	const char *slash = NULL;
	const char *c;
	gboolean needs_validation = FALSE;
#if 0
	gboolean node_is_required = FALSE;
#endif
#ifndef USE_IDN
	char *node = NULL;
	char *domain;
#endif
	JabberID *jid;

	if (!str)
		return NULL;

	for (c = str; *c != '\0'; c++)
	{
		switch (*c) {
			case '@':
				if (!slash) {
					if (at) {
						/* Multiple @'s in the node/domain portion, not a valid JID! */
						return NULL;
					}
					if (c == str) {
						/* JIDs cannot start with @ */
						return NULL;
					}
					if (c[1] == '\0') {
						/* JIDs cannot end with @ */
						return NULL;
					}
					at = c;
				}
				break;

			case '/':
				if (!slash) {
					if (c == str) {
						/* JIDs cannot start with / */
						return NULL;
					}
					if (c[1] == '\0' && !allow_terminating_slash) {
						/* JIDs cannot end with / */
						return NULL;
					}
					slash = c;
				}
				break;

			default:
				/* characters allowed everywhere */
				if ((*c >= 'a' && *c <= 'z')
						|| (*c >= '0' && *c <= '9')
						|| (*c >= 'A' && *c <= 'Z')
						|| *c == '.' || *c == '-')
					/* We're good */
					break;

#if 0
				if (slash != NULL) {
					/* characters allowed only in the resource */
					if (implement_me)
						/* We're good */
						break;
				}

				/* characters allowed only in the node */
				if (implement_me) {
					/*
					 * Ok, this character is valid, but only if it's a part
					 * of the node and not the domain.  But we don't know
					 * if "c" is a part of the node or the domain until after
					 * we've found the @.  So set a flag for now and check
					 * that we found an @ later.
					 */
					node_is_required = TRUE;
					break;
				}
#endif

				/*
				 * Hmm, this character is a bit more exotic.  Better fall
				 * back to using the more expensive UTF-8 compliant
				 * stringprep functions.
				 */
				needs_validation = TRUE;
				break;
		}
	}

#if 0
	if (node_is_required && at == NULL)
		/* Found invalid characters in the domain */
		return NULL;
#endif

	if (!needs_validation) {
		/* JID is made of only ASCII characters--just lowercase and return */
		jid = g_new0(JabberID, 1);

		if (at) {
			jid->node = g_ascii_strdown(str, at - str);
			if (slash) {
				jid->domain = g_ascii_strdown(at + 1, slash - (at + 1));
				if (*(slash + 1))
					jid->resource = g_strdup(slash + 1);
			} else {
				jid->domain = g_ascii_strdown(at + 1, -1);
			}
		} else {
			if (slash) {
				jid->domain = g_ascii_strdown(str, slash - str);
				if (*(slash + 1))
					jid->resource = g_strdup(slash + 1);
			} else {
				jid->domain = g_ascii_strdown(str, -1);
			}
		}
		return jid;
	}

	/*
	 * If we get here, there are some non-ASCII chars in the string, so
	 * we'll need to validate it, normalize, and finally do a full jabber
	 * nodeprep on the jid.
	 */

	if (!g_utf8_validate(str, -1, NULL))
		return NULL;

#ifdef USE_IDN
	return jabber_idn_validate(str, at, slash, c /* points to the null */);
#else /* USE_IDN */

	jid = g_new0(JabberID, 1);

	/* normalization */
	if(at) {
		node = g_utf8_casefold(str, at-str);
		if(slash) {
			domain = g_utf8_casefold(at+1, slash-(at+1));
			if (*(slash + 1))
				jid->resource = g_utf8_normalize(slash+1, -1, G_NORMALIZE_NFKC);
		} else {
			domain = g_utf8_casefold(at+1, -1);
		}
	} else {
		if(slash) {
			domain = g_utf8_casefold(str, slash-str);
			if (*(slash + 1))
				jid->resource = g_utf8_normalize(slash+1, -1, G_NORMALIZE_NFKC);
		} else {
			domain = g_utf8_casefold(str, -1);
		}
	}

	if (node) {
		jid->node = g_utf8_normalize(node, -1, G_NORMALIZE_NFKC);
		g_free(node);
	}

	if (domain) {
		jid->domain = g_utf8_normalize(domain, -1, G_NORMALIZE_NFKC);
		g_free(domain);
	}

	/* and finally the jabber nodeprep */
	if(!jabber_nodeprep_validate(jid->node) ||
			!jabber_domain_validate(jid->domain) ||
			!jabber_resourceprep_validate(jid->resource)) {
		jabber_id_free(jid);
		return NULL;
	}

	return jid;
#endif /* USE_IDN */
}

void
jabber_id_free(JabberID *jid)
{
	if(jid) {
		g_free(jid->node);
		g_free(jid->domain);
		g_free(jid->resource);
		g_free(jid);
	}
}


gboolean
jabber_id_equal(const JabberID *jid1, const JabberID *jid2)
{
	if (!jid1 && !jid2) {
		/* Both are null therefore equal */
		return TRUE;
	}

	if (!jid1 || !jid2) {
		/* One is null, other is non-null, therefore not equal */
		return FALSE;
	}

	return purple_strequal(jid1->node, jid2->node) &&
			purple_strequal(jid1->domain, jid2->domain) &&
			purple_strequal(jid1->resource, jid2->resource);
}

char *jabber_get_domain(const char *in)
{
	JabberID *jid = jabber_id_new(in);
	char *out;

	if (!jid)
		return NULL;

	out = g_strdup(jid->domain);
	jabber_id_free(jid);

	return out;
}

char *jabber_get_resource(const char *in)
{
	JabberID *jid = jabber_id_new(in);
	char *out;

	if(!jid)
		return NULL;

	out = g_strdup(jid->resource);
	jabber_id_free(jid);

	return out;
}

JabberID *
jabber_id_to_bare_jid(const JabberID *jid)
{
	JabberID *result = g_new0(JabberID, 1);

	result->node = g_strdup(jid->node);
	result->domain = g_strdup(jid->domain);

	return result;
}

char *
jabber_get_bare_jid(const char *in)
{
	JabberID *jid = jabber_id_new(in);
	char *out;

	if (!jid)
		return NULL;
	out = jabber_id_get_bare_jid(jid);
	jabber_id_free(jid);

	return out;
}

char *
jabber_id_get_bare_jid(const JabberID *jid)
{
	g_return_val_if_fail(jid != NULL, NULL);

	return g_strconcat(jid->node ? jid->node : "",
	                   jid->node ? "@" : "",
	                   jid->domain,
	                   NULL);
}

char *
jabber_id_get_full_jid(const JabberID *jid)
{
	g_return_val_if_fail(jid != NULL, NULL);

	return g_strconcat(jid->node ? jid->node : "",
	                   jid->node ? "@" : "",
	                   jid->domain,
	                   jid->resource ? "/" : "",
	                   jid->resource ? jid->resource : "",
	                   NULL);
}

gboolean
jabber_jid_is_domain(const char *jid)
{
	const char *c;

	for (c = jid; *c; ++c) {
		if (*c == '@' || *c == '/')
			return FALSE;
	}

	return TRUE;
}


JabberID *
jabber_id_new(const char *str)
{
	return jabber_id_new_internal(str, FALSE);
}

const char *jabber_normalize(const PurpleAccount *account, const char *in)
{
	PurpleConnection *gc = account ? account->gc : NULL;
	JabberStream *js = gc ? gc->proto_data : NULL;
	static char buf[3072]; /* maximum legal length of a jabber jid */
	JabberID *jid;

	jid = jabber_id_new_internal(in, TRUE);
	if(!jid)
		return NULL;

	if(js && jid->node && jid->resource &&
			jabber_chat_find(js, jid->node, jid->domain))
		g_snprintf(buf, sizeof(buf), "%s@%s/%s", jid->node, jid->domain,
				jid->resource);
	else
		g_snprintf(buf, sizeof(buf), "%s%s%s", jid->node ? jid->node : "",
				jid->node ? "@" : "", jid->domain);

	jabber_id_free(jid);

	return buf;
}

gboolean
jabber_is_own_server(JabberStream *js, const char *str)
{
	JabberID *jid;
	gboolean equal;

	if (str == NULL)
		return FALSE;

	g_return_val_if_fail(*str != '\0', FALSE);

	jid = jabber_id_new(str);
	if (!jid)
		return FALSE;

	equal = (jid->node == NULL &&
	         g_str_equal(jid->domain, js->user->domain) &&
	         jid->resource == NULL);
	jabber_id_free(jid);
	return equal;
}

gboolean
jabber_is_own_account(JabberStream *js, const char *str)
{
	JabberID *jid;
	gboolean equal;

	if (str == NULL)
		return TRUE;

	g_return_val_if_fail(*str != '\0', FALSE);

	jid = jabber_id_new(str);
	if (!jid)
		return FALSE;

	equal = (purple_strequal(jid->node, js->user->node) &&
	         g_str_equal(jid->domain, js->user->domain) &&
	         (jid->resource == NULL ||
	             g_str_equal(jid->resource, js->user->resource)));
	jabber_id_free(jid);
	return equal;
}

static const struct {
		const char *status_id; /* link to core */
		const char *show; /* The show child's cdata in a presence stanza */
		const char *readable; /* readable representation */
		JabberBuddyState state;
} jabber_statuses[] = {
	{ "offline",       NULL,   N_("Offline"),        JABBER_BUDDY_STATE_UNAVAILABLE },
	{ "available",     NULL,   N_("Available"),      JABBER_BUDDY_STATE_ONLINE},
	{ "freeforchat",   "chat", N_("Chatty"),         JABBER_BUDDY_STATE_CHAT },
	{ "away",          "away", N_("Away"),           JABBER_BUDDY_STATE_AWAY },
	{ "extended_away", "xa",   N_("Extended Away"),  JABBER_BUDDY_STATE_XA },
	{ "dnd",           "dnd",  N_("Do Not Disturb"), JABBER_BUDDY_STATE_DND },
	{ "error",         NULL,   N_("Error"),          JABBER_BUDDY_STATE_ERROR }
};

const char *
jabber_buddy_state_get_name(const JabberBuddyState state)
{
	int i;
	for (i = 0; i < G_N_ELEMENTS(jabber_statuses); ++i)
		if (jabber_statuses[i].state == state)
			return _(jabber_statuses[i].readable);

	return _("Unknown");
}

JabberBuddyState
jabber_buddy_status_id_get_state(const char *id)
{
	int i;
	if (!id)
		return JABBER_BUDDY_STATE_UNKNOWN;

	for (i = 0; i < G_N_ELEMENTS(jabber_statuses); ++i)
		if (g_str_equal(id, jabber_statuses[i].status_id))
			return jabber_statuses[i].state;

	return JABBER_BUDDY_STATE_UNKNOWN;
}

JabberBuddyState jabber_buddy_show_get_state(const char *id)
{
	int i;

	g_return_val_if_fail(id != NULL, JABBER_BUDDY_STATE_UNKNOWN);

	for (i = 0; i < G_N_ELEMENTS(jabber_statuses); ++i)
		if (jabber_statuses[i].show && g_str_equal(id, jabber_statuses[i].show))
			return jabber_statuses[i].state;

	purple_debug_warning("jabber", "Invalid value of presence <show/> "
	                     "attribute: %s\n", id);
	return JABBER_BUDDY_STATE_UNKNOWN;
}

const char *
jabber_buddy_state_get_show(JabberBuddyState state)
{
	int i;
	for (i = 0; i < G_N_ELEMENTS(jabber_statuses); ++i)
		if (state == jabber_statuses[i].state)
			return jabber_statuses[i].show;

	return NULL;
}

const char *
jabber_buddy_state_get_status_id(JabberBuddyState state)
{
	int i;
	for (i = 0; i < G_N_ELEMENTS(jabber_statuses); ++i)
		if (state == jabber_statuses[i].state)
			return jabber_statuses[i].status_id;

	return NULL;
}

char *
jabber_calculate_data_hash(gconstpointer data, size_t len,
    const gchar *hash_algo)
{
	PurpleCipherContext *context;
	static gchar digest[129]; /* 512 bits hex + \0 */

	context = purple_cipher_context_new_by_name(hash_algo, NULL);
	if (context == NULL)
	{
		purple_debug_error("jabber", "Could not find %s cipher\n", hash_algo);
		g_return_val_if_reached(NULL);
	}

	/* Hash the data */
	purple_cipher_context_append(context, data, len);
	if (!purple_cipher_context_digest_to_str(context, sizeof(digest), digest, NULL))
	{
		purple_debug_error("jabber", "Failed to get digest for %s cipher.\n",
		    hash_algo);
		g_return_val_if_reached(NULL);
	}
	purple_cipher_context_destroy(context);

	return g_strdup(digest);
}

