/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#include "internal.h"

#include "mdns_interface.h"
#include "debug.h"
#include "buddy.h"
#include "bonjour.h"

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>

#include <avahi-common/address.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/strlst.h>

#include <avahi-glib/glib-malloc.h>
#include <avahi-glib/glib-watch.h>

/* Avahi only defines the types that it actually uses (which at this time doesn't include NULL) */
#ifndef AVAHI_DNS_TYPE_NULL
#define AVAHI_DNS_TYPE_NULL 0x0A
#endif

/* data used by avahi bonjour implementation */
typedef struct _avahi_session_impl_data {
	AvahiClient *client;
	AvahiGLibPoll *glib_poll;
	AvahiServiceBrowser *sb;
	AvahiEntryGroup *group;
	AvahiEntryGroup *buddy_icon_group;
} AvahiSessionImplData;

typedef struct _avahi_buddy_service_resolver_data {
	AvahiServiceResolver *resolver;
	AvahiIfIndex interface;
	AvahiProtocol protocol;
	gchar *name;
	gchar *type;
	gchar *domain;
	/* This is a reference to the entry in BonjourBuddy->ips */
	const char *ip;
} AvahiSvcResolverData;

typedef struct _avahi_buddy_impl_data {
	GSList *resolvers;
	AvahiRecordBrowser *buddy_icon_rec_browser;
} AvahiBuddyImplData;

static gint
_find_resolver_data(gconstpointer a, gconstpointer b) {
	const AvahiSvcResolverData *rd_a = a;
	const AvahiSvcResolverData *rd_b = b;
	gint ret = 1;

	if(rd_a->interface == rd_b->interface
			&& rd_a->protocol == rd_b->protocol
			&& !strcmp(rd_a->name, rd_b->name)
			&& !strcmp(rd_a->type, rd_b->type)
			&& !strcmp(rd_a->domain, rd_b->domain)) {
		ret = 0;
	}

	return ret;
}

static gint
_find_resolver_data_by_resolver(gconstpointer a, gconstpointer b) {
	const AvahiSvcResolverData *rd_a = a;
	const AvahiServiceResolver *resolver = b;
	gint ret = 1;

	if(rd_a->resolver == resolver)
		ret = 0;

	return ret;
}

static void
_cleanup_resolver_data(AvahiSvcResolverData *rd) {
	if (rd->resolver)
		avahi_service_resolver_free(rd->resolver);
	g_free(rd->name);
	g_free(rd->type);
	g_free(rd->domain);
	g_free(rd);
}


static void
_resolver_callback(AvahiServiceResolver *r, AvahiIfIndex interface, AvahiProtocol protocol,
		  AvahiResolverEvent event, const char *name, const char *type, const char *domain,
		  const char *host_name, const AvahiAddress *a, uint16_t port, AvahiStringList *txt,
		  AvahiLookupResultFlags flags, void *userdata) {

	PurpleBuddy *pb;
	BonjourBuddy *bb;
	PurpleAccount *account = userdata;
	AvahiStringList *l;
	size_t size;
	char *key, *value;
	char ip[AVAHI_ADDRESS_STR_MAX];
	AvahiBuddyImplData *b_impl;
	AvahiSvcResolverData *rd;
	GSList *res;

	g_return_if_fail(r != NULL);

	pb = purple_find_buddy(account, name);
	bb = (pb != NULL) ? purple_buddy_get_protocol_data(pb) : NULL;

	switch (event) {
		case AVAHI_RESOLVER_FAILURE:
			purple_debug_error("bonjour", "_resolve_callback - Failure: %s\n",
				avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));

			avahi_service_resolver_free(r);
			if (bb != NULL) {
				b_impl = bb->mdns_impl_data;
				res = g_slist_find_custom(b_impl->resolvers, r, _find_resolver_data_by_resolver);
				if (res != NULL) {
					rd = res->data;
					b_impl->resolvers = g_slist_remove_link(b_impl->resolvers, res);

					/* We've already freed the resolver */
					rd->resolver = NULL;
					_cleanup_resolver_data(rd);

					/* If this was the last resolver, remove the buddy */
					if (b_impl->resolvers == NULL)
						bonjour_buddy_signed_off(pb);
				}
			}
			break;
		case AVAHI_RESOLVER_FOUND:

			purple_debug_info("bonjour", "_resolve_callback - name:%s account:%p bb:%p\n",
				name, account, bb);

			/* create a buddy record */
			if (bb == NULL)
				bb = bonjour_buddy_new(name, account);
			b_impl = bb->mdns_impl_data;

			/* If we're reusing an existing buddy, it may be a new resolver or an existing one. */
			res = g_slist_find_custom(b_impl->resolvers, r, _find_resolver_data_by_resolver);
			if (res != NULL)
				rd = res->data;
			else {
				rd = g_new0(AvahiSvcResolverData, 1);
				rd->resolver = r;
				rd->interface = interface;
				rd->protocol = protocol;
				rd->name = g_strdup(name);
				rd->type = g_strdup(type);
				rd->domain = g_strdup(domain);

				b_impl->resolvers = g_slist_prepend(b_impl->resolvers, rd);
			}


			/* Get the ip as a string */
			ip[0] = '\0';
			avahi_address_snprint(ip, AVAHI_ADDRESS_STR_MAX, a);

			if (protocol == AVAHI_PROTO_INET6)
				append_iface_if_linklocal(ip, interface);

			purple_debug_info("bonjour", "_resolve_callback - name:%s ip:%s prev_ip:%s\n",
				name, ip, rd->ip);

			if (rd->ip == NULL || strcmp(rd->ip, ip) != 0) {
				/* We store duplicates in bb->ips, so we always remove the one */
				if (rd->ip != NULL) {
					bb->ips = g_slist_remove(bb->ips, rd->ip);
					g_free((gchar *) rd->ip);
				}
				/* IPv6 goes at the front of the list and IPv4 at the end so that we "prefer" IPv6, if present */
				if (protocol == AVAHI_PROTO_INET6) {
					rd->ip = g_strdup_printf("%s", ip);
					bb->ips = g_slist_prepend(bb->ips, (gchar *) rd->ip);
				} else {
					rd->ip = g_strdup(ip);
					bb->ips = g_slist_append(bb->ips, (gchar *) rd->ip);
				}
			}

			bb->port_p2pj = port;

			/* Obtain the parameters from the text_record */
			clear_bonjour_buddy_values(bb);
			for(l = txt; l != NULL; l = l->next) {
				if (avahi_string_list_get_pair(l, &key, &value, &size) < 0)
					continue;
				set_bonjour_buddy_value(bb, key, value, size);
				/* TODO: Since we're using the glib allocator, I think we
				 * can use the values instead of re-copying them */
				avahi_free(key);
				avahi_free(value);
			}

			if (!bonjour_buddy_check(bb)) {
				b_impl->resolvers = g_slist_remove(b_impl->resolvers, rd);
				_cleanup_resolver_data(rd);
				/* If this was the last resolver, remove the buddy */
				if (b_impl->resolvers == NULL) {
					if (pb != NULL)
						bonjour_buddy_signed_off(pb);
					else
						bonjour_buddy_delete(bb);
				}
			} else
				/* Add or update the buddy in our buddy list */
				bonjour_buddy_add_to_purple(bb, pb);

			break;
		default:
			purple_debug_info("bonjour", "Unrecognized Service Resolver event: %d.\n", event);
	}

}

static void
_browser_callback(AvahiServiceBrowser *b, AvahiIfIndex interface,
		  AvahiProtocol protocol, AvahiBrowserEvent event,
		  const char *name, const char *type, const char *domain,
		  AvahiLookupResultFlags flags, void *userdata) {

	PurpleAccount *account = userdata;
	PurpleBuddy *pb = NULL;

	switch (event) {
		case AVAHI_BROWSER_FAILURE:
			purple_debug_error("bonjour", "_browser_callback - Failure: %s\n",
				avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b))));
			/* TODO: This is an error that should be handled. */
			break;
		case AVAHI_BROWSER_NEW:
			/* A new peer has joined the network and uses iChat bonjour */
			purple_debug_info("bonjour", "_browser_callback - new service\n");
			/* Make sure it isn't us */
			if (purple_utf8_strcasecmp(name, bonjour_get_jid(account)) != 0) {
				if (!avahi_service_resolver_new(avahi_service_browser_get_client(b),
						interface, protocol, name, type, domain, protocol,
						0, _resolver_callback, account)) {
					purple_debug_warning("bonjour", "_browser_callback -- Error initiating resolver: %s\n",
						avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b))));
				}
			}
			break;
		case AVAHI_BROWSER_REMOVE:
			purple_debug_info("bonjour", "_browser_callback - Remove service\n");
			pb = purple_find_buddy(account, name);
			if (pb != NULL) {
				BonjourBuddy *bb = purple_buddy_get_protocol_data(pb);
				AvahiBuddyImplData *b_impl;
				GSList *l;
				AvahiSvcResolverData *rd_search;

				g_return_if_fail(bb != NULL);

				b_impl = bb->mdns_impl_data;

				/* There may be multiple presences, we should only get rid of this one */

				rd_search = g_new0(AvahiSvcResolverData, 1);
				rd_search->interface = interface;
				rd_search->protocol = protocol;
				rd_search->name = (gchar *) name;
				rd_search->type = (gchar *) type;
				rd_search->domain = (gchar *) domain;

				l = g_slist_find_custom(b_impl->resolvers, rd_search, _find_resolver_data);

				g_free(rd_search);

				if (l != NULL) {
					AvahiSvcResolverData *rd = l->data;
					b_impl->resolvers = g_slist_remove(b_impl->resolvers, rd);
					/* This IP is no longer available */
					if (rd->ip != NULL) {
						bb->ips = g_slist_remove(bb->ips, rd->ip);
						g_free((gchar *) rd->ip);
					}
					_cleanup_resolver_data(rd);

					/* If this was the last resolver, remove the buddy */
					if (b_impl->resolvers == NULL)
						bonjour_buddy_signed_off(pb);
				}
			}
			break;
		case AVAHI_BROWSER_ALL_FOR_NOW:
		case AVAHI_BROWSER_CACHE_EXHAUSTED:
			break;
		default:
			purple_debug_info("bonjour", "Unrecognized Service browser event: %d.\n", event);
	}
}

static void
_buddy_icon_group_cb(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
	BonjourDnsSd *data = userdata;
	AvahiSessionImplData *idata = data->mdns_impl_data;

	g_return_if_fail(g == idata->buddy_icon_group || idata->buddy_icon_group == NULL);

	switch(state) {
		case AVAHI_ENTRY_GROUP_ESTABLISHED:
			purple_debug_info("bonjour", "Successfully registered buddy icon data.\n");
			break;
		case AVAHI_ENTRY_GROUP_COLLISION:
			purple_debug_error("bonjour", "Collision registering buddy icon data.\n");
			break;
		case AVAHI_ENTRY_GROUP_FAILURE:
			purple_debug_error("bonjour", "Error registering buddy icon data: %s.\n",
				avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
			break;
		case AVAHI_ENTRY_GROUP_UNCOMMITED:
		case AVAHI_ENTRY_GROUP_REGISTERING:
			break;
	}

}

static void
_entry_group_cb(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata) {
	AvahiSessionImplData *idata = userdata;

	g_return_if_fail(g == idata->group || idata->group == NULL);

	switch(state) {
		case AVAHI_ENTRY_GROUP_ESTABLISHED:
			purple_debug_info("bonjour", "Successfully registered service.\n");
			break;
		case AVAHI_ENTRY_GROUP_COLLISION:
			purple_debug_error("bonjour", "Collision registering entry group.\n");
			/* TODO: Handle error - this should log out the account. (Possibly with "wants to die")*/
			break;
		case AVAHI_ENTRY_GROUP_FAILURE:
			purple_debug_error("bonjour", "Error registering entry group: %s\n.",
				avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
			/* TODO: Handle error - this should log out the account.*/
			break;
		case AVAHI_ENTRY_GROUP_UNCOMMITED:
		case AVAHI_ENTRY_GROUP_REGISTERING:
			break;
	}

}

static void
_buddy_icon_record_cb(AvahiRecordBrowser *b, AvahiIfIndex interface, AvahiProtocol protocol,
		      AvahiBrowserEvent event, const char *name, uint16_t clazz, uint16_t type,
		      const void *rdata, size_t size, AvahiLookupResultFlags flags, void *userdata) {
	BonjourBuddy *buddy = userdata;
	AvahiBuddyImplData *idata = buddy->mdns_impl_data;

	switch (event) {
		case AVAHI_BROWSER_CACHE_EXHAUSTED:
		case AVAHI_BROWSER_ALL_FOR_NOW:
			/* Ignore these "meta" informational events */
			return;
		case AVAHI_BROWSER_NEW:
			bonjour_buddy_got_buddy_icon(buddy, rdata, size);
			break;
		case AVAHI_BROWSER_REMOVE:
		case AVAHI_BROWSER_FAILURE:
			purple_debug_error("bonjour", "Error retrieving buddy icon record: %s\n",
				avahi_strerror(avahi_client_errno(avahi_record_browser_get_client(b))));
			break;
	}

	/* Stop listening */
	avahi_record_browser_free(b);
	if (idata->buddy_icon_rec_browser == b) {
		idata->buddy_icon_rec_browser = NULL;
	}
}

/****************************
 * mdns_interface functions *
 ****************************/

gboolean _mdns_init_session(BonjourDnsSd *data) {
	AvahiSessionImplData *idata = g_new0(AvahiSessionImplData, 1);
	const AvahiPoll *poll_api;
	int error;

	/* Tell avahi to use g_malloc and g_free */
	avahi_set_allocator (avahi_glib_allocator ());

	/* This currently depends on the glib mainloop,
	 * we should make it use the libpurple abstraction */

	idata->glib_poll = avahi_glib_poll_new(NULL, G_PRIORITY_DEFAULT);

	poll_api = avahi_glib_poll_get(idata->glib_poll);

	idata->client = avahi_client_new(poll_api, 0, NULL, data, &error);

	if (idata->client == NULL) {
		purple_debug_error("bonjour", "Error initializing Avahi: %s\n", avahi_strerror(error));
		avahi_glib_poll_free(idata->glib_poll);
		g_free(idata);
		return FALSE;
	}

	data->mdns_impl_data = idata;

	bonjour_dns_sd_set_jid(data->account, avahi_client_get_host_name(idata->client));

	return TRUE;
}

gboolean _mdns_publish(BonjourDnsSd *data, PublishType type, GSList *records) {
	int publish_result = 0;
	AvahiSessionImplData *idata = data->mdns_impl_data;
	AvahiStringList *lst = NULL;

	g_return_val_if_fail(idata != NULL, FALSE);

	if (!idata->group) {
		idata->group = avahi_entry_group_new(idata->client,
						     _entry_group_cb, idata);
		if (!idata->group) {
			purple_debug_error("bonjour",
				"Unable to initialize the data for the mDNS (%s).\n",
				avahi_strerror(avahi_client_errno(idata->client)));
			return FALSE;
		}
	}

	while (records) {
		PurpleKeyValuePair *kvp = records->data;
		lst = avahi_string_list_add_pair(lst, kvp->key, kvp->value);
		records = records->next;
	}

	/* Publish the service */
	switch (type) {
		case PUBLISH_START:
			publish_result = avahi_entry_group_add_service_strlst(
				idata->group, AVAHI_IF_UNSPEC,
				AVAHI_PROTO_UNSPEC, 0,
				bonjour_get_jid(data->account),
				LINK_LOCAL_RECORD_NAME, NULL, NULL, data->port_p2pj, lst);
			break;
		case PUBLISH_UPDATE:
			publish_result = avahi_entry_group_update_service_txt_strlst(
				idata->group, AVAHI_IF_UNSPEC,
				AVAHI_PROTO_UNSPEC, 0,
				bonjour_get_jid(data->account),
				LINK_LOCAL_RECORD_NAME, NULL, lst);
			break;
	}

	/* Free the memory used by temp data */
	avahi_string_list_free(lst);

	if (publish_result < 0) {
		purple_debug_error("bonjour",
			"Failed to add the " LINK_LOCAL_RECORD_NAME " service. Error: %s\n",
			avahi_strerror(publish_result));
		return FALSE;
	}

	if (type == PUBLISH_START
			&& (publish_result = avahi_entry_group_commit(idata->group)) < 0) {
		purple_debug_error("bonjour",
			"Failed to commit " LINK_LOCAL_RECORD_NAME " service. Error: %s\n",
			avahi_strerror(publish_result));
		return FALSE;
	}

	return TRUE;
}

gboolean _mdns_browse(BonjourDnsSd *data) {
	AvahiSessionImplData *idata = data->mdns_impl_data;

	g_return_val_if_fail(idata != NULL, FALSE);

	idata->sb = avahi_service_browser_new(idata->client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, LINK_LOCAL_RECORD_NAME, NULL, 0, _browser_callback, data->account);
	if (!idata->sb) {

		purple_debug_error("bonjour",
			"Unable to initialize service browser.  Error: %s.\n",
			avahi_strerror(avahi_client_errno(idata->client)));
		return FALSE;
	}

	return TRUE;
}

gboolean _mdns_set_buddy_icon_data(BonjourDnsSd *data, gconstpointer avatar_data, gsize avatar_len) {
	AvahiSessionImplData *idata = data->mdns_impl_data;

	if (idata == NULL || idata->client == NULL)
		return FALSE;

	if (avatar_data != NULL) {
		gboolean new_group = FALSE;
		gchar *svc_name;
		int ret;
		AvahiPublishFlags flags = 0;

		if (idata->buddy_icon_group == NULL) {
			purple_debug_info("bonjour", "Setting new buddy icon.\n");
			new_group = TRUE;

			idata->buddy_icon_group = avahi_entry_group_new(idata->client,
				_buddy_icon_group_cb, data);
		} else {
			purple_debug_info("bonjour", "Updating existing buddy icon.\n");
			flags |= AVAHI_PUBLISH_UPDATE;
		}

		if (idata->buddy_icon_group == NULL) {
			purple_debug_error("bonjour",
				"Unable to initialize the buddy icon group (%s).\n",
				avahi_strerror(avahi_client_errno(idata->client)));
			return FALSE;
		}

		svc_name = g_strdup_printf("%s." LINK_LOCAL_RECORD_NAME "local",
				bonjour_get_jid(data->account));

		ret = avahi_entry_group_add_record(idata->buddy_icon_group, AVAHI_IF_UNSPEC,
			AVAHI_PROTO_UNSPEC, flags, svc_name,
			AVAHI_DNS_CLASS_IN, AVAHI_DNS_TYPE_NULL, 120, avatar_data, avatar_len);

		g_free(svc_name);

		if (ret < 0) {
			purple_debug_error("bonjour",
				"Failed to register buddy icon. Error: %s\n", avahi_strerror(ret));
			if (new_group) {
				avahi_entry_group_free(idata->buddy_icon_group);
				idata->buddy_icon_group = NULL;
			}
			return FALSE;
		}

		if (new_group && (ret = avahi_entry_group_commit(idata->buddy_icon_group)) < 0) {
			purple_debug_error("bonjour",
				"Failed to commit buddy icon group. Error: %s\n", avahi_strerror(ret));
			if (new_group) {
				avahi_entry_group_free(idata->buddy_icon_group);
				idata->buddy_icon_group = NULL;
			}
			return FALSE;
		}
	} else if (idata->buddy_icon_group != NULL) {
		purple_debug_info("bonjour", "Removing existing buddy icon.\n");
		avahi_entry_group_free(idata->buddy_icon_group);
		idata->buddy_icon_group = NULL;
	}

	return TRUE;
}

void _mdns_stop(BonjourDnsSd *data) {
	AvahiSessionImplData *idata = data->mdns_impl_data;

	if (idata == NULL || idata->client == NULL)
		return;

	if (idata->sb != NULL)
		avahi_service_browser_free(idata->sb);

	avahi_client_free(idata->client);
	avahi_glib_poll_free(idata->glib_poll);

	g_free(idata);

	data->mdns_impl_data = NULL;
}

void _mdns_init_buddy(BonjourBuddy *buddy) {
	buddy->mdns_impl_data = g_new0(AvahiBuddyImplData, 1);
}

void _mdns_delete_buddy(BonjourBuddy *buddy) {
	AvahiBuddyImplData *idata = buddy->mdns_impl_data;

	g_return_if_fail(idata != NULL);

	if (idata->buddy_icon_rec_browser != NULL)
		avahi_record_browser_free(idata->buddy_icon_rec_browser);

	while(idata->resolvers != NULL) {
		AvahiSvcResolverData *rd = idata->resolvers->data;
		_cleanup_resolver_data(rd);
		idata->resolvers = g_slist_delete_link(idata->resolvers, idata->resolvers);
	}

	g_free(idata);

	buddy->mdns_impl_data = NULL;
}

void _mdns_retrieve_buddy_icon(BonjourBuddy* buddy) {
	PurpleConnection *conn = purple_account_get_connection(buddy->account);
	BonjourData *bd = conn->proto_data;
	AvahiSessionImplData *session_idata = bd->dns_sd_data->mdns_impl_data;
	AvahiBuddyImplData *idata = buddy->mdns_impl_data;
	gchar *name;

	g_return_if_fail(idata != NULL);

	if (idata->buddy_icon_rec_browser != NULL)
		avahi_record_browser_free(idata->buddy_icon_rec_browser);

	purple_debug_info("bonjour", "Retrieving buddy icon for '%s'.\n", buddy->name);

	name = g_strdup_printf("%s." LINK_LOCAL_RECORD_NAME "local", buddy->name);
	idata->buddy_icon_rec_browser = avahi_record_browser_new(session_idata->client, AVAHI_IF_UNSPEC,
		AVAHI_PROTO_UNSPEC, name, AVAHI_DNS_CLASS_IN, AVAHI_DNS_TYPE_NULL, 0,
		_buddy_icon_record_cb, buddy);
	g_free(name);

	if (!idata->buddy_icon_rec_browser) {
		purple_debug_error("bonjour",
			"Unable to initialize buddy icon record browser.  Error: %s.\n",
			avahi_strerror(avahi_client_errno(session_idata->client)));
	}

}

