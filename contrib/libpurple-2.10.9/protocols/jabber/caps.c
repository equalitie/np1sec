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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 */

#include "internal.h"

#include "debug.h"
#include "caps.h"
#include "cipher.h"
#include "iq.h"
#include "presence.h"
#include "util.h"
#include "xdata.h"

#define JABBER_CAPS_FILENAME "xmpp-caps.xml"

typedef struct _JabberDataFormField {
	gchar *var;
	GList *values;
} JabberDataFormField;

static GHashTable *capstable = NULL; /* JabberCapsTuple -> JabberCapsClientInfo */
static GHashTable *nodetable = NULL; /* char *node -> JabberCapsNodeExts */
static guint       save_timer = 0;

/* Free a GList of allocated char* */
static void
free_string_glist(GList *list)
{
	while (list) {
		g_free(list->data);
		list = g_list_delete_link(list, list);
	}
}

static JabberCapsNodeExts*
jabber_caps_node_exts_ref(JabberCapsNodeExts *exts)
{
	g_return_val_if_fail(exts != NULL, NULL);

	++exts->ref;
	return exts;
}

static void
jabber_caps_node_exts_unref(JabberCapsNodeExts *exts)
{
	if (exts == NULL)
		return;

	g_return_if_fail(exts->ref != 0);

	if (--exts->ref != 0)
		return;

	g_hash_table_destroy(exts->exts);
	g_free(exts);
}

static guint jabber_caps_hash(gconstpointer data) {
	const JabberCapsTuple *key = data;
	guint nodehash = g_str_hash(key->node);
	guint verhash  = g_str_hash(key->ver);
	/*
	 * 'hash' was optional in XEP-0115 v1.4 and g_str_hash crashes on NULL >:O.
	 * Okay, maybe I've played too much Zelda, but that looks like
	 * a Deku Shrub...
	 */
	guint hashhash = (key->hash ? g_str_hash(key->hash) : 0);
	return nodehash ^ verhash ^ hashhash;
}

static gboolean jabber_caps_compare(gconstpointer v1, gconstpointer v2) {
	const JabberCapsTuple *name1 = v1;
	const JabberCapsTuple *name2 = v2;

	return g_str_equal(name1->node, name2->node) &&
	       g_str_equal(name1->ver, name2->ver) &&
	       purple_strequal(name1->hash, name2->hash);
}

static void
jabber_caps_client_info_destroy(JabberCapsClientInfo *info)
{
	if (info == NULL)
		return;

	while(info->identities) {
		JabberIdentity *id = info->identities->data;
		g_free(id->category);
		g_free(id->type);
		g_free(id->name);
		g_free(id->lang);
		g_free(id);
		info->identities = g_list_delete_link(info->identities, info->identities);
	}

	free_string_glist(info->features);

	while (info->forms) {
		xmlnode_free(info->forms->data);
		info->forms = g_list_delete_link(info->forms, info->forms);
	}

	jabber_caps_node_exts_unref(info->exts);

	g_free((char *)info->tuple.node);
	g_free((char *)info->tuple.ver);
	g_free((char *)info->tuple.hash);

	g_free(info);
}

/* NOTE: Takes a reference to the exts, unref it if you don't really want to
 * keep it around. */
static JabberCapsNodeExts*
jabber_caps_find_exts_by_node(const char *node)
{
	JabberCapsNodeExts *exts;
	if (NULL == (exts = g_hash_table_lookup(nodetable, node))) {
		exts = g_new0(JabberCapsNodeExts, 1);
		exts->exts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
		                                   (GDestroyNotify)free_string_glist);
		g_hash_table_insert(nodetable, g_strdup(node), jabber_caps_node_exts_ref(exts));
	}

	return jabber_caps_node_exts_ref(exts);
}

static void
exts_to_xmlnode(gconstpointer key, gconstpointer value, gpointer user_data)
{
	const char *identifier = key;
	const GList *features = value, *node;
	xmlnode *client = user_data, *ext, *feature;

	ext = xmlnode_new_child(client, "ext");
	xmlnode_set_attrib(ext, "identifier", identifier);

	for (node = features; node; node = node->next) {
		feature = xmlnode_new_child(ext, "feature");
		xmlnode_set_attrib(feature, "var", (const gchar *)node->data);
	}
}

static void jabber_caps_store_client(gpointer key, gpointer value, gpointer user_data) {
	const JabberCapsTuple *tuple = key;
	const JabberCapsClientInfo *props = value;
	xmlnode *root = user_data;
	xmlnode *client = xmlnode_new_child(root, "client");
	GList *iter;

	xmlnode_set_attrib(client, "node", tuple->node);
	xmlnode_set_attrib(client, "ver", tuple->ver);
	if (tuple->hash)
		xmlnode_set_attrib(client, "hash", tuple->hash);
	for(iter = props->identities; iter; iter = g_list_next(iter)) {
		JabberIdentity *id = iter->data;
		xmlnode *identity = xmlnode_new_child(client, "identity");
		xmlnode_set_attrib(identity, "category", id->category);
		xmlnode_set_attrib(identity, "type", id->type);
		if (id->name)
			xmlnode_set_attrib(identity, "name", id->name);
		if (id->lang)
			xmlnode_set_attrib(identity, "lang", id->lang);
	}

	for(iter = props->features; iter; iter = g_list_next(iter)) {
		const char *feat = iter->data;
		xmlnode *feature = xmlnode_new_child(client, "feature");
		xmlnode_set_attrib(feature, "var", feat);
	}

	for(iter = props->forms; iter; iter = g_list_next(iter)) {
		/* FIXME: See #7814 */
		xmlnode *xdata = iter->data;
		xmlnode_insert_child(client, xmlnode_copy(xdata));
	}

	/* TODO: Ideally, only save this once-per-node... */
	if (props->exts)
		g_hash_table_foreach(props->exts->exts, (GHFunc)exts_to_xmlnode, client);
}

static gboolean
do_jabber_caps_store(gpointer data)
{
	char *str;
	int length = 0;
	xmlnode *root = xmlnode_new("capabilities");
	g_hash_table_foreach(capstable, jabber_caps_store_client, root);
	str = xmlnode_to_formatted_str(root, &length);
	xmlnode_free(root);
	purple_util_write_data_to_file(JABBER_CAPS_FILENAME, str, length);
	g_free(str);

	save_timer = 0;
	return FALSE;
}

static void
schedule_caps_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, do_jabber_caps_store, NULL);
}

static void
jabber_caps_load(void)
{
	xmlnode *capsdata = purple_util_read_xml_from_file(JABBER_CAPS_FILENAME, "XMPP capabilities cache");
	xmlnode *client;

	if(!capsdata)
		return;

	if (!g_str_equal(capsdata->name, "capabilities")) {
		xmlnode_free(capsdata);
		return;
	}

	for (client = capsdata->child; client; client = client->next) {
		if (client->type != XMLNODE_TYPE_TAG)
			continue;
		if (g_str_equal(client->name, "client")) {
			JabberCapsClientInfo *value = g_new0(JabberCapsClientInfo, 1);
			JabberCapsTuple *key = (JabberCapsTuple*)&value->tuple;
			xmlnode *child;
			JabberCapsNodeExts *exts = NULL;
			key->node = g_strdup(xmlnode_get_attrib(client,"node"));
			key->ver  = g_strdup(xmlnode_get_attrib(client,"ver"));
			key->hash = g_strdup(xmlnode_get_attrib(client,"hash"));

			/* v1.3 capabilities */
			if (key->hash == NULL)
				exts = jabber_caps_find_exts_by_node(key->node);

			for (child = client->child; child; child = child->next) {
				if (child->type != XMLNODE_TYPE_TAG)
					continue;
				if (g_str_equal(child->name, "feature")) {
					const char *var = xmlnode_get_attrib(child, "var");
					if(!var)
						continue;
					value->features = g_list_append(value->features,g_strdup(var));
				} else if (g_str_equal(child->name, "identity")) {
					const char *category = xmlnode_get_attrib(child, "category");
					const char *type = xmlnode_get_attrib(child, "type");
					const char *name = xmlnode_get_attrib(child, "name");
					const char *lang = xmlnode_get_attrib(child, "lang");
					JabberIdentity *id;

					if (!category || !type)
						continue;

					id = g_new0(JabberIdentity, 1);
					id->category = g_strdup(category);
					id->type = g_strdup(type);
					id->name = g_strdup(name);
					id->lang = g_strdup(lang);

					value->identities = g_list_append(value->identities,id);
				} else if (g_str_equal(child->name, "x")) {
					/* TODO: See #7814 -- this might cause problems if anyone
					 * ever actually specifies forms. In fact, for this to
					 * work properly, that bug needs to be fixed in
					 * xmlnode_from_str, not the output version... */
					value->forms = g_list_append(value->forms, xmlnode_copy(child));
				} else if (g_str_equal(child->name, "ext")) {
					if (key->hash != NULL)
						purple_debug_warning("jabber", "Ignoring exts when reading new-style caps\n");
					else {
						/* TODO: Do we care about reading in the identities listed here? */
						const char *identifier = xmlnode_get_attrib(child, "identifier");
						xmlnode *node;
						GList *features = NULL;

						if (!identifier)
							continue;

						for (node = child->child; node; node = node->next) {
							if (node->type != XMLNODE_TYPE_TAG)
								continue;
							if (g_str_equal(node->name, "feature")) {
								const char *var = xmlnode_get_attrib(node, "var");
								if (!var)
									continue;
								features = g_list_prepend(features, g_strdup(var));
							}
						}

						if (features) {
							g_hash_table_insert(exts->exts, g_strdup(identifier),
							                    features);
						} else
							purple_debug_warning("jabber", "Caps ext %s had no features.\n",
							                     identifier);
					}
				}
			}

			value->exts = exts;
			g_hash_table_replace(capstable, key, value);

		}
	}
	xmlnode_free(capsdata);
}

void jabber_caps_init(void)
{
	nodetable = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)jabber_caps_node_exts_unref);
	capstable = g_hash_table_new_full(jabber_caps_hash, jabber_caps_compare, NULL, (GDestroyNotify)jabber_caps_client_info_destroy);
	jabber_caps_load();
}

void jabber_caps_uninit(void)
{
	if (save_timer != 0) {
		purple_timeout_remove(save_timer);
		save_timer = 0;
		do_jabber_caps_store(NULL);
	}
	g_hash_table_destroy(capstable);
	g_hash_table_destroy(nodetable);
	capstable = nodetable = NULL;
}

gboolean jabber_caps_exts_known(const JabberCapsClientInfo *info,
                                char **exts)
{
	int i;
	g_return_val_if_fail(info != NULL, FALSE);

	if (!exts)
		return TRUE;

	for (i = 0; exts[i]; ++i) {
		/* Hack since we advertise the ext along with v1.5 caps but don't
		 * store any exts */
		if (g_str_equal(exts[i], "voice-v1") && !info->exts)
			continue;
		if (!info->exts ||
				!g_hash_table_lookup(info->exts->exts, exts[i]))
			return FALSE;
	}

	return TRUE;
}

typedef struct _jabber_caps_cbplususerdata {
	guint ref;

	jabber_caps_get_info_cb cb;
	gpointer cb_data;

	char *who;
	char *node;
	char *ver;
	char *hash;

	JabberCapsClientInfo *info;

	GList *exts;
	guint extOutstanding;
	JabberCapsNodeExts *node_exts;
} jabber_caps_cbplususerdata;

static jabber_caps_cbplususerdata*
cbplususerdata_ref(jabber_caps_cbplususerdata *data)
{
	g_return_val_if_fail(data != NULL, NULL);

	++data->ref;
	return data;
}

static void
cbplususerdata_unref(jabber_caps_cbplususerdata *data)
{
	if (data == NULL)
		return;

	g_return_if_fail(data->ref != 0);

	if (--data->ref > 0)
		return;

	g_free(data->who);
	g_free(data->node);
	g_free(data->ver);
	g_free(data->hash);

	/* If we have info here, it's already in the capstable, so don't free it */
	if (data->exts)
		free_string_glist(data->exts);
	if (data->node_exts)
		jabber_caps_node_exts_unref(data->node_exts);
	g_free(data);
}

static void
jabber_caps_get_info_complete(jabber_caps_cbplususerdata *userdata)
{
	if (userdata->cb) {
		userdata->cb(userdata->info, userdata->exts, userdata->cb_data);
		userdata->info = NULL;
		userdata->exts = NULL;
	}

	if (userdata->ref != 1)
		purple_debug_warning("jabber", "Lost a reference to caps cbdata: %d\n",
		                     userdata->ref);
}

static void
jabber_caps_client_iqcb(JabberStream *js, const char *from, JabberIqType type,
                        const char *id, xmlnode *packet, gpointer data)
{
	xmlnode *query = xmlnode_get_child_with_namespace(packet, "query",
		NS_DISCO_INFO);
	jabber_caps_cbplususerdata *userdata = data;
	JabberCapsClientInfo *info = NULL, *value;
	JabberCapsTuple key;

	if (!query || type == JABBER_IQ_ERROR) {
		/* Any outstanding exts will be dealt with via ref-counting */
		userdata->cb(NULL, NULL, userdata->cb_data);
		cbplususerdata_unref(userdata);
		return;
	}

	/* check hash */
	info = jabber_caps_parse_client_info(query);

	/* Only validate if these are v1.5 capabilities */
	if (userdata->hash) {
		gchar *hash = NULL;
		/*
		 * TODO: If you add *any* hash here, make sure the checksum buffer
		 * size in jabber_caps_calculate_hash is large enough. The cipher API
		 * doesn't seem to offer a "Get the hash size" function(?).
		 */
		if (g_str_equal(userdata->hash, "sha-1")) {
			hash = jabber_caps_calculate_hash(info, "sha1");
		} else if (g_str_equal(userdata->hash, "md5")) {
			hash = jabber_caps_calculate_hash(info, "md5");
		}

		if (!hash || !g_str_equal(hash, userdata->ver)) {
			purple_debug_warning("jabber", "Could not validate caps info from "
			                     "%s. Expected %s, got %s\n",
			                     xmlnode_get_attrib(packet, "from"),
			                     userdata->ver, hash ? hash : "(null)");

			userdata->cb(NULL, NULL, userdata->cb_data);
			jabber_caps_client_info_destroy(info);
			cbplususerdata_unref(userdata);
			g_free(hash);
			return;
		}

		g_free(hash);
	}

	if (!userdata->hash && userdata->node_exts) {
		/* If the ClientInfo doesn't have information about the exts, give them
		 * ours (along with our ref) */
		info->exts = userdata->node_exts;
		userdata->node_exts = NULL;
	}

	key.node = userdata->node;
	key.ver  = userdata->ver;
	key.hash = userdata->hash;

	/* Use the copy of this data already in the table if it exists or insert
	 * a new one if we need to */
	if ((value = g_hash_table_lookup(capstable, &key))) {
		jabber_caps_client_info_destroy(info);
		info = value;
	} else {
		JabberCapsTuple *n_key = (JabberCapsTuple *)&info->tuple;
		n_key->node = userdata->node;
		n_key->ver  = userdata->ver;
		n_key->hash = userdata->hash;
		userdata->node = userdata->ver = userdata->hash = NULL;

		/* The capstable gets a reference */
		g_hash_table_insert(capstable, n_key, info);
		schedule_caps_save();
	}

	userdata->info = info;

	if (userdata->extOutstanding == 0)
		jabber_caps_get_info_complete(userdata);

	cbplususerdata_unref(userdata);
}

typedef struct {
	const char *name;
	jabber_caps_cbplususerdata *data;
} ext_iq_data;

static void
jabber_caps_ext_iqcb(JabberStream *js, const char *from, JabberIqType type,
                     const char *id, xmlnode *packet, gpointer data)
{
	xmlnode *query = xmlnode_get_child_with_namespace(packet, "query",
		NS_DISCO_INFO);
	xmlnode *child;
	ext_iq_data *userdata = data;
	GList *features = NULL;
	JabberCapsNodeExts *node_exts;

	if (!query || type == JABBER_IQ_ERROR) {
		cbplususerdata_unref(userdata->data);
		g_free(userdata);
		return;
	}

	node_exts = (userdata->data->info ? userdata->data->info->exts :
	                                    userdata->data->node_exts);

	/* TODO: I don't see how this can actually happen, but it crashed khc. */
	if (!node_exts) {
		purple_debug_error("jabber", "Couldn't find JabberCapsNodeExts. If you "
				"see this, please tell darkrain42 and save your debug log.\n"
				"JabberCapsClientInfo = %p\n", userdata->data->info);


		/* Try once more to find the exts and then fail */
		node_exts = jabber_caps_find_exts_by_node(userdata->data->node);
		if (node_exts) {
			purple_debug_info("jabber", "Found the exts on the second try.\n");
			if (userdata->data->info)
				userdata->data->info->exts = node_exts;
			else
				userdata->data->node_exts = node_exts;
		} else {
			cbplususerdata_unref(userdata->data);
			g_free(userdata);
			g_return_if_reached();
		}
	}

	/* So, we decrement this after checking for an error, which means that
	 * if there *is* an error, we'll never call the callback passed to
	 * jabber_caps_get_info. We will still free all of our data, though.
	 */
	--userdata->data->extOutstanding;

	for (child = xmlnode_get_child(query, "feature"); child;
	        child = xmlnode_get_next_twin(child)) {
		const char *var = xmlnode_get_attrib(child, "var");
		if (var)
			features = g_list_prepend(features, g_strdup(var));
	}

	g_hash_table_insert(node_exts->exts, g_strdup(userdata->name), features);
	schedule_caps_save();

	/* Are we done? */
	if (userdata->data->info && userdata->data->extOutstanding == 0)
		jabber_caps_get_info_complete(userdata->data);

	cbplususerdata_unref(userdata->data);
	g_free(userdata);
}

void jabber_caps_get_info(JabberStream *js, const char *who, const char *node,
        const char *ver, const char *hash, char **exts,
        jabber_caps_get_info_cb cb, gpointer user_data)
{
	JabberCapsClientInfo *info;
	JabberCapsTuple key;
	jabber_caps_cbplususerdata *userdata;

	if (exts && hash) {
		purple_debug_misc("jabber", "Ignoring exts in new-style caps from %s\n",
		                  who);
		g_strfreev(exts);
		exts = NULL;
	}

	/* Using this in a read-only fashion, so the cast is OK */
	key.node = (char *)node;
	key.ver = (char *)ver;
	key.hash = (char *)hash;

	info = g_hash_table_lookup(capstable, &key);
	if (info && hash) {
		/* v1.5 - We already have all the information we care about */
		if (cb)
			cb(info, NULL, user_data);
		return;
	}

	userdata = g_new0(jabber_caps_cbplususerdata, 1);
	/* We start out with 0 references. Every query takes one */
	userdata->cb = cb;
	userdata->cb_data = user_data;
	userdata->who = g_strdup(who);
	userdata->node = g_strdup(node);
	userdata->ver = g_strdup(ver);
	userdata->hash = g_strdup(hash);

	if (info) {
		userdata->info = info;
	} else {
		/* If we don't have the basic information about the client, we need
		 * to fetch it. */
		JabberIq *iq;
		xmlnode *query;
		char *nodever;

		iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_DISCO_INFO);
		query = xmlnode_get_child_with_namespace(iq->node, "query",
					NS_DISCO_INFO);
		nodever = g_strdup_printf("%s#%s", node, ver);
		xmlnode_set_attrib(query, "node", nodever);
		g_free(nodever);
		xmlnode_set_attrib(iq->node, "to", who);

		cbplususerdata_ref(userdata);

		jabber_iq_set_callback(iq, jabber_caps_client_iqcb, userdata);
		jabber_iq_send(iq);
	}

	/* Are there any exts that we don't recognize? */
	if (exts) {
		JabberCapsNodeExts *node_exts;
		int i;

		if (info) {
			if (info->exts)
				node_exts = info->exts;
			else
				node_exts = info->exts = jabber_caps_find_exts_by_node(node);
		} else
			/* We'll put it in later once we have the client info */
			node_exts = userdata->node_exts = jabber_caps_find_exts_by_node(node);

		for (i = 0; exts[i]; ++i) {
			userdata->exts = g_list_prepend(userdata->exts, exts[i]);
			/* Look it up if we don't already know what it means */
			if (!g_hash_table_lookup(node_exts->exts, exts[i])) {
				JabberIq *iq;
				xmlnode *query;
				char *nodeext;
				ext_iq_data *cbdata = g_new(ext_iq_data, 1);

				cbdata->name = exts[i];
				cbdata->data = cbplususerdata_ref(userdata);

				iq = jabber_iq_new_query(js, JABBER_IQ_GET, NS_DISCO_INFO);
				query = xmlnode_get_child_with_namespace(iq->node, "query",
				            NS_DISCO_INFO);
				nodeext = g_strdup_printf("%s#%s", node, exts[i]);
				xmlnode_set_attrib(query, "node", nodeext);
				g_free(nodeext);
				xmlnode_set_attrib(iq->node, "to", who);

				jabber_iq_set_callback(iq, jabber_caps_ext_iqcb, cbdata);
				jabber_iq_send(iq);

				++userdata->extOutstanding;
			}
			exts[i] = NULL;
		}
		/* All the strings are now part of the GList, so don't need
		 * g_strfreev. */
		g_free(exts);
	}

	if (userdata->info && userdata->extOutstanding == 0) {
		/* Start with 1 ref so the below functions are happy */
		userdata->ref = 1;

		/* We have everything we need right now */
		jabber_caps_get_info_complete(userdata);
		cbplususerdata_unref(userdata);
	}
}

static gint
jabber_xdata_compare(gconstpointer a, gconstpointer b)
{
	const xmlnode *aformtypefield = a;
	const xmlnode *bformtypefield = b;
	char *aformtype;
	char *bformtype;
	int result;

	aformtype = jabber_x_data_get_formtype(aformtypefield);
	bformtype = jabber_x_data_get_formtype(bformtypefield);

	result = strcmp(aformtype, bformtype);
	g_free(aformtype);
	g_free(bformtype);
	return result;
}

JabberCapsClientInfo *jabber_caps_parse_client_info(xmlnode *query)
{
	xmlnode *child;
	JabberCapsClientInfo *info;

	if (!query || !g_str_equal(query->name, "query") ||
			!purple_strequal(query->xmlns, NS_DISCO_INFO))
		return NULL;

	info = g_new0(JabberCapsClientInfo, 1);

	for(child = query->child; child; child = child->next) {
		if (child->type != XMLNODE_TYPE_TAG)
			continue;
		if (g_str_equal(child->name, "identity")) {
			/* parse identity */
			const char *category = xmlnode_get_attrib(child, "category");
			const char *type = xmlnode_get_attrib(child, "type");
			const char *name = xmlnode_get_attrib(child, "name");
			const char *lang = xmlnode_get_attrib(child, "lang");
			JabberIdentity *id;

			if (!category || !type)
				continue;

			id = g_new0(JabberIdentity, 1);
			id->category = g_strdup(category);
			id->type = g_strdup(type);
			id->name = g_strdup(name);
			id->lang = g_strdup(lang);

			info->identities = g_list_append(info->identities, id);
		} else if (g_str_equal(child->name, "feature")) {
			/* parse feature */
			const char *var = xmlnode_get_attrib(child, "var");
			if (var)
				info->features = g_list_prepend(info->features, g_strdup(var));
		} else if (g_str_equal(child->name, "x")) {
			if (purple_strequal(child->xmlns, "jabber:x:data")) {
				/* x-data form */
				xmlnode *dataform = xmlnode_copy(child);
				info->forms = g_list_append(info->forms, dataform);
			}
		}
	}
	return info;
}

static gint jabber_caps_xdata_field_compare(gconstpointer a, gconstpointer b)
{
	const JabberDataFormField *ac = a;
	const JabberDataFormField *bc = b;

	return strcmp(ac->var, bc->var);
}

static GList* jabber_caps_xdata_get_fields(const xmlnode *x)
{
	GList *fields = NULL;
	xmlnode *field;

	if (!x)
		return NULL;

	for (field = xmlnode_get_child(x, "field"); field; field = xmlnode_get_next_twin(field)) {
		xmlnode *value;
		JabberDataFormField *xdatafield = g_new0(JabberDataFormField, 1);
		xdatafield->var = g_strdup(xmlnode_get_attrib(field, "var"));

		for (value = xmlnode_get_child(field, "value"); value; value = xmlnode_get_next_twin(value)) {
			gchar *val = xmlnode_get_data(value);
			xdatafield->values = g_list_append(xdatafield->values, val);
		}

		xdatafield->values = g_list_sort(xdatafield->values, (GCompareFunc)strcmp);
		fields = g_list_append(fields, xdatafield);
	}

	fields = g_list_sort(fields, jabber_caps_xdata_field_compare);
	return fields;
}

static void
append_escaped_string(PurpleCipherContext *context, const gchar *str)
{
	if (str && *str) {
		char *tmp = g_markup_escape_text(str, -1);
		purple_cipher_context_append(context, (const guchar *)tmp, strlen(tmp));
		g_free(tmp);
	}

	purple_cipher_context_append(context, (const guchar *)"<", 1);
}

gchar *jabber_caps_calculate_hash(JabberCapsClientInfo *info, const char *hash)
{
	GList *node;
	PurpleCipherContext *context;
	guint8 checksum[20];
	gsize checksum_size = 20;
	gboolean success;

	if (!info || !(context = purple_cipher_context_new_by_name(hash, NULL)))
		return NULL;

	/* sort identities, features and x-data forms */
	info->identities = g_list_sort(info->identities, jabber_identity_compare);
	info->features = g_list_sort(info->features, (GCompareFunc)strcmp);
	info->forms = g_list_sort(info->forms, jabber_xdata_compare);

	/* Add identities to the hash data */
	for (node = info->identities; node; node = node->next) {
		JabberIdentity *id = (JabberIdentity*)node->data;
		char *category = g_markup_escape_text(id->category, -1);
		char *type = g_markup_escape_text(id->type, -1);
		char *lang = NULL;
		char *name = NULL;
		char *tmp;

		if (id->lang)
			lang = g_markup_escape_text(id->lang, -1);
		if (id->name)
			name = g_markup_escape_text(id->name, -1);

		tmp = g_strconcat(category, "/", type, "/", lang ? lang : "",
		                  "/", name ? name : "", "<", NULL);

		purple_cipher_context_append(context, (const guchar *)tmp, strlen(tmp));

		g_free(tmp);
		g_free(category);
		g_free(type);
		g_free(lang);
		g_free(name);
	}

	/* concat features to the verification string */
	for (node = info->features; node; node = node->next) {
		append_escaped_string(context, node->data);
	}

	/* concat x-data forms to the verification string */
	for(node = info->forms; node; node = node->next) {
		xmlnode *data = (xmlnode *)node->data;
		gchar *formtype = jabber_x_data_get_formtype(data);
		GList *fields = jabber_caps_xdata_get_fields(data);

		/* append FORM_TYPE's field value to the verification string */
		append_escaped_string(context, formtype);
		g_free(formtype);

		while (fields) {
			GList *value;
			JabberDataFormField *field = (JabberDataFormField*)fields->data;

			if (!g_str_equal(field->var, "FORM_TYPE")) {
				/* Append the "var" attribute */
				append_escaped_string(context, field->var);
				/* Append <value/> elements' cdata */
				for (value = field->values; value; value = value->next) {
					append_escaped_string(context, value->data);
					g_free(value->data);
				}
			}

			g_free(field->var);
			g_list_free(field->values);

			fields = g_list_delete_link(fields, fields);
		}
	}

	/* generate hash */
	success = purple_cipher_context_digest(context, checksum_size,
	                                       checksum, &checksum_size);

	purple_cipher_context_destroy(context);

	return (success ? purple_base64_encode(checksum, checksum_size) : NULL);
}

void jabber_caps_calculate_own_hash(JabberStream *js) {
	JabberCapsClientInfo info;
	GList *iter = 0;
	GList *features = 0;

	if (!jabber_identities && !jabber_features) {
		/* This really shouldn't ever happen */
		purple_debug_warning("jabber", "No features or identities, cannot calculate own caps hash.\n");
		g_free(js->caps_hash);
		js->caps_hash = NULL;
		return;
	}

	/* build the currently-supported list of features */
	if (jabber_features) {
		for (iter = jabber_features; iter; iter = iter->next) {
			JabberFeature *feat = iter->data;
			if(!feat->is_enabled || feat->is_enabled(js, feat->namespace)) {
				features = g_list_append(features, feat->namespace);
			}
		}
	}

	info.features = features;
	/* TODO: This copy can go away, I think, since jabber_identities
	 * is pre-sorted, so the sort in calculate_hash should be idempotent.
	 * However, I want to test that. --darkrain
	 */
	info.identities = g_list_copy(jabber_identities);
	info.forms = NULL;

	g_free(js->caps_hash);
	js->caps_hash = jabber_caps_calculate_hash(&info, "sha1");
	g_list_free(info.identities);
	g_list_free(info.features);
}

const gchar* jabber_caps_get_own_hash(JabberStream *js)
{
	if (!js->caps_hash)
		jabber_caps_calculate_own_hash(js);

	return js->caps_hash;
}

void jabber_caps_broadcast_change()
{
	GList *node, *accounts = purple_accounts_get_all_active();

	for (node = accounts; node; node = node->next) {
		PurpleAccount *account = node->data;
		const char *prpl_id = purple_account_get_protocol_id(account);
		if (g_str_equal("prpl-jabber", prpl_id) && purple_account_is_connected(account)) {
			PurpleConnection *gc = purple_account_get_connection(account);
			jabber_presence_send(gc->proto_data, TRUE);
		}
	}

	g_list_free(accounts);
}

