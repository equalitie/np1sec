/*
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
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
#include "debug.h"

#include "buddy.h"
#include "mdns_interface.h"
#include "dns_sd_proxy.h"
#include "mdns_common.h"
#include "bonjour.h"

static GSList *pending_buddies = NULL;

typedef struct _dnssd_service_ref_handler {
	DNSServiceRef sdRef;
	PurpleAccount *account;
	guint input_handler;
} DnsSDServiceRefHandlerData;

/* data used by win32 bonjour implementation */
typedef struct _win32_session_impl_data {
	DnsSDServiceRefHandlerData *presence_query;
	DnsSDServiceRefHandlerData *browser_query;
	DNSRecordRef buddy_icon_rec;
} Win32SessionImplData;

typedef struct _win32_buddy_service_resolver_data {
	DnsSDServiceRefHandlerData *txt_query;
	uint32_t if_idx;
	gchar *name;
	gchar *type;
	gchar *domain;
	/* This is a reference to the entry in BonjourBuddy->ips */
	const char *ip;
} Win32SvcResolverData;

typedef struct _win32_buddy_impl_data {
	GSList *resolvers;
	DnsSDServiceRefHandlerData *null_query;
} Win32BuddyImplData;

/* data structure for the resolve callback */
typedef struct _ResolveCallbackArgs {
	DnsSDServiceRefHandlerData *resolver_query;
	PurpleAccount *account;
	BonjourBuddy *bb;
	Win32SvcResolverData *res_data;
	gchar *full_service_name;
} ResolveCallbackArgs;


static gint
_find_resolver_data(gconstpointer a, gconstpointer b) {
	const Win32SvcResolverData *rd_a = a;
	const Win32SvcResolverData *rd_b = b;
	gint ret = 1;

	if(rd_a->if_idx == rd_b->if_idx
			&& !strcmp(rd_a->name, rd_b->name)
			&& !strcmp(rd_a->type, rd_b->type)
			&& !strcmp(rd_a->domain, rd_b->domain)) {
		ret = 0;
	}

	return ret;
}

static void
_cleanup_resolver_data(Win32SvcResolverData *rd) {
	if (rd->txt_query != NULL) {
		purple_input_remove(rd->txt_query->input_handler);
		DNSServiceRefDeallocate(rd->txt_query->sdRef);
		g_free(rd->txt_query);
	}
	g_free(rd->name);
	g_free(rd->type);
	g_free(rd->domain);
	g_free(rd);
}

static void
_mdns_handle_event(gpointer data, gint source, PurpleInputCondition condition) {
	DnsSDServiceRefHandlerData *srh = data;
	DNSServiceErrorType errorCode = DNSServiceProcessResult(srh->sdRef);
	if (errorCode != kDNSServiceErr_NoError) {
		purple_debug_error("bonjour", "Error (%d) handling mDNS response.\n", errorCode);
		/* This happens when the mDNSResponder goes down, I haven't seen it happen any other time (in my limited testing) */
		if (errorCode == kDNSServiceErr_Unknown) {
			purple_connection_error_reason(srh->account->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Error communicating with local mDNSResponder."));
		}
	}
}

static void
_mdns_parse_text_record(BonjourBuddy *buddy, const char *record, uint16_t record_len)
{
	const char *txt_entry;
	uint8_t txt_len;
	int i;

	clear_bonjour_buddy_values(buddy);
	for (i = 0; buddy_TXT_records[i] != NULL; i++) {
		txt_entry = TXTRecordGetValuePtr(record_len, record, buddy_TXT_records[i], &txt_len);
		if (txt_entry != NULL)
			set_bonjour_buddy_value(buddy, buddy_TXT_records[i], txt_entry, txt_len);
	}
}

static void DNSSD_API
_mdns_record_query_callback(DNSServiceRef DNSServiceRef, DNSServiceFlags flags,
	uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname,
	uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata,
	uint32_t ttl, void *context)
{

	if (errorCode != kDNSServiceErr_NoError) {
		purple_debug_error("bonjour", "record query - callback error (%d).\n", errorCode);
		/* TODO: Probably should remove the buddy when this happens */
	} else if (flags & kDNSServiceFlagsAdd) {
		if (rrtype == kDNSServiceType_TXT) {
			/* New Buddy */
			BonjourBuddy *bb = (BonjourBuddy*) context;
			_mdns_parse_text_record(bb, rdata, rdlen);
			bonjour_buddy_add_to_purple(bb, NULL);
		} else if (rrtype == kDNSServiceType_NULL) {
			/* Buddy Icon response */
			BonjourBuddy *bb = (BonjourBuddy*) context;
			Win32BuddyImplData *idata = bb->mdns_impl_data;

			g_return_if_fail(idata != NULL);

			bonjour_buddy_got_buddy_icon(bb, rdata, rdlen);

			/* We've got what we need; stop listening */
			purple_input_remove(idata->null_query->input_handler);
			DNSServiceRefDeallocate(idata->null_query->sdRef);
			g_free(idata->null_query);
			idata->null_query = NULL;
		}
	}
}

static void DNSSD_API
_mdns_resolve_host_callback(DNSServiceRef sdRef, DNSServiceFlags flags,
	uint32_t interfaceIndex, DNSServiceErrorType errorCode,
	const char *hostname, const struct sockaddr *address,
	uint32_t ttl, void *context)
{
	ResolveCallbackArgs *args = (ResolveCallbackArgs*) context;
	Win32BuddyImplData *idata = args->bb->mdns_impl_data;
	gboolean delete_buddy = FALSE;
	PurpleBuddy *pb = NULL;

	purple_input_remove(args->resolver_query->input_handler);
	DNSServiceRefDeallocate(args->resolver_query->sdRef);
	g_free(args->resolver_query);
	args->resolver_query = NULL;

	if ((pb = purple_find_buddy(args->account, args->res_data->name))) {
		if (pb->proto_data != args->bb) {
			purple_debug_error("bonjour", "Found purple buddy for %s not matching bonjour buddy record.",
				args->res_data->name);
			goto cleanup;
		}
	/* Make sure that the BonjourBuddy associated with this request is still around */
	} else if (g_slist_find(pending_buddies, args->bb) == NULL) {
		purple_debug_error("bonjour", "host resolution - complete, but buddy no longer pending.\n");
		goto cleanup;
	}

	if (errorCode != kDNSServiceErr_NoError) {
		purple_debug_error("bonjour", "host resolution - callback error (%d).\n", errorCode);
		delete_buddy = TRUE;
	} else {
		DNSServiceRef txt_query_sr;

		/* finally, set up the continuous txt record watcher, and add the buddy to purple */
		errorCode = DNSServiceQueryRecord(&txt_query_sr, kDNSServiceFlagsLongLivedQuery,
				kDNSServiceInterfaceIndexAny, args->full_service_name, kDNSServiceType_TXT,
				kDNSServiceClass_IN, _mdns_record_query_callback, args->bb);
		if (errorCode == kDNSServiceErr_NoError) {
			const char *ip = inet_ntoa(((struct sockaddr_in *) address)->sin_addr);

			purple_debug_info("bonjour", "Found buddy %s at %s:%d\n", args->bb->name, ip, args->bb->port_p2pj);

			args->bb->ips = g_slist_prepend(args->bb->ips, g_strdup(ip));
			args->res_data->ip = args->bb->ips->data;

			args->res_data->txt_query = g_new(DnsSDServiceRefHandlerData, 1);
			args->res_data->txt_query->sdRef = txt_query_sr;
			args->res_data->txt_query->account = args->account;

			args->res_data->txt_query->input_handler = purple_input_add(DNSServiceRefSockFD(txt_query_sr),
				PURPLE_INPUT_READ, _mdns_handle_event, args->res_data->txt_query);

			bonjour_buddy_add_to_purple(args->bb, NULL);
		} else {
			purple_debug_error("bonjour", "Unable to set up record watcher for buddy %s (%d)\n", args->bb->name, errorCode);
			delete_buddy = TRUE;
		}

	}

	cleanup:

	if (delete_buddy) {
		idata->resolvers = g_slist_remove(idata->resolvers, args->res_data);
		_cleanup_resolver_data(args->res_data);

		/* If this was the last resolver, remove the buddy */
		if (idata->resolvers == NULL) {
			if (pb)
				bonjour_buddy_signed_off(pb);
			else
				bonjour_buddy_delete(args->bb);

			/* Remove from the pending list */
			pending_buddies = g_slist_remove(pending_buddies, args->bb);
		}
	} else {
		/* Remove from the pending list */
		pending_buddies = g_slist_remove(pending_buddies, args->bb);
	}

	/* free the remaining args memory */
	g_free(args->full_service_name);
	g_free(args);
}

static void DNSSD_API
_mdns_service_resolve_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode,
    const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const unsigned char *txtRecord, void *context)
{
	ResolveCallbackArgs *args = (ResolveCallbackArgs*) context;
	Win32BuddyImplData *idata = args->bb->mdns_impl_data;

	/* remove the input fd and destroy the service ref */
	purple_input_remove(args->resolver_query->input_handler);
	DNSServiceRefDeallocate(args->resolver_query->sdRef);

	if (errorCode != kDNSServiceErr_NoError)
		purple_debug_error("bonjour", "service resolver - callback error. (%d)\n", errorCode);
	else {
		DNSServiceRef getaddrinfo_sr;
		/* set more arguments, and start the host resolver */
		errorCode = DNSServiceGetAddrInfo(&getaddrinfo_sr, 0, interfaceIndex,
			kDNSServiceProtocol_IPv4, hosttarget, _mdns_resolve_host_callback, args);
		if (errorCode != kDNSServiceErr_NoError)
			purple_debug_error("bonjour", "service resolver - host resolution failed.\n");
		else {
			args->resolver_query->sdRef = getaddrinfo_sr;
			args->resolver_query->input_handler = purple_input_add(DNSServiceRefSockFD(getaddrinfo_sr),
				PURPLE_INPUT_READ, _mdns_handle_event, args->resolver_query);
			args->full_service_name = g_strdup(fullname);

			/* TODO: Should this be per resolver? */
			args->bb->port_p2pj = ntohs(port);

			/* We don't want to hit the cleanup code */
			return;
		}
	}

	/* If we get this far, clean up */

	g_free(args->resolver_query);
	args->resolver_query = NULL;

	idata->resolvers = g_slist_remove(idata->resolvers, args->res_data);
	_cleanup_resolver_data(args->res_data);

	/* If this was the last resolver, remove the buddy */
	if (idata->resolvers == NULL) {
		PurpleBuddy *pb;
		/* See if this is now attached to a PurpleBuddy */
		if ((pb = purple_find_buddy(args->account, args->bb->name)))
			bonjour_buddy_signed_off(pb);
		else {
			/* Remove from the pending list */
			pending_buddies = g_slist_remove(pending_buddies, args->bb);
			bonjour_buddy_delete(args->bb);
		}
	}

	g_free(args);

}

static void DNSSD_API
_mdns_service_register_callback(DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode,
				const char *name, const char *regtype, const char *domain, void *context) {

	/* TODO: deal with collision */
	if (errorCode != kDNSServiceErr_NoError)
		purple_debug_error("bonjour", "service advertisement - callback error (%d).\n", errorCode);
	else
		purple_debug_info("bonjour", "service advertisement - callback.\n");
}

static void DNSSD_API
_mdns_service_browse_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
    DNSServiceErrorType errorCode, const char *serviceName, const char *regtype, const char *replyDomain, void *context)
{
	PurpleAccount *account = (PurpleAccount*)context;

	if (errorCode != kDNSServiceErr_NoError)
		purple_debug_error("bonjour", "service browser - callback error (%d)\n", errorCode);
	else if (flags & kDNSServiceFlagsAdd) {
		/* A presence service instance has been discovered... check it isn't us! */
		if (purple_utf8_strcasecmp(serviceName, bonjour_get_jid(account)) != 0) {
			DNSServiceErrorType resErrorCode;
			/* OK, lets go ahead and resolve it to add to the buddy list */
			ResolveCallbackArgs *args = g_new0(ResolveCallbackArgs, 1);
			DNSServiceRef resolver_sr;

			purple_debug_info("bonjour", "Received new record for '%s' on iface %u (%s, %s)\n",
							  serviceName, interfaceIndex, regtype ? regtype : "",
							  replyDomain ? replyDomain : "");

			resErrorCode = DNSServiceResolve(&resolver_sr, 0, interfaceIndex, serviceName, regtype,
					replyDomain, _mdns_service_resolve_callback, args);
			if (resErrorCode == kDNSServiceErr_NoError) {
				GSList *tmp = pending_buddies;
				PurpleBuddy *pb;
				BonjourBuddy* bb = NULL;
				Win32SvcResolverData *rd;
				Win32BuddyImplData *idata;

				/* Is there an existing buddy? */
				if ((pb = purple_find_buddy(account, serviceName)))
					bb = pb->proto_data;
				/* Is there a pending buddy? */
				else {
					while (tmp) {
						BonjourBuddy *bb_tmp = tmp->data;
						if (!strcmp(bb_tmp->name, serviceName)) {
							bb = bb_tmp;
							break;
						}
						tmp = tmp->next;
					}
				}

				if (bb == NULL) {
					bb = bonjour_buddy_new(serviceName, account);

					/* This is only necessary for the wacky case where someone previously manually added a buddy. */
					if (pb == NULL)
						pending_buddies = g_slist_prepend(pending_buddies, bb);
					else
						pb->proto_data = bb;
				}

				rd = g_new0(Win32SvcResolverData, 1);
				rd->if_idx = interfaceIndex;
				rd->name = g_strdup(serviceName);
				rd->type = g_strdup(regtype);
				rd->domain = g_strdup(replyDomain);

				idata = bb->mdns_impl_data;
				idata->resolvers = g_slist_prepend(idata->resolvers, rd);

				args->bb = bb;
				args->res_data = rd;
				args->account = account;

				args->resolver_query = g_new(DnsSDServiceRefHandlerData, 1);
				args->resolver_query->sdRef = resolver_sr;
				args->resolver_query->account = account;
				/* get a file descriptor for this service ref, and add it to the input list */
				args->resolver_query->input_handler = purple_input_add(DNSServiceRefSockFD(resolver_sr),
					PURPLE_INPUT_READ, _mdns_handle_event, args->resolver_query);
			} else {
				purple_debug_error("bonjour", "service browser - failed to resolve service. (%d)\n", resErrorCode);
				g_free(args);
			}
		}
	} else {
		PurpleBuddy *pb = NULL;

		/* A peer has sent a goodbye packet, remove them from the buddy list */
		purple_debug_info("bonjour", "Received remove notification for '%s' on iface %u (%s, %s)\n",
						  serviceName, interfaceIndex, regtype ? regtype : "",
						  replyDomain ? replyDomain : "");

		pb = purple_find_buddy(account, serviceName);
		if (pb != NULL) {
			GSList *l;
			/* There may be multiple presences, we should only get rid of this one */
			Win32SvcResolverData *rd_search;
			BonjourBuddy *bb = pb->proto_data;
			Win32BuddyImplData *idata;

			g_return_if_fail(bb != NULL);

			idata = bb->mdns_impl_data;

			rd_search = g_new0(Win32SvcResolverData, 1);
			rd_search->if_idx = interfaceIndex;
			rd_search->name = (gchar *) serviceName;
			rd_search->type = (gchar *) regtype;
			rd_search->domain = (gchar *) replyDomain;

			l = g_slist_find_custom(idata->resolvers, rd_search, _find_resolver_data);

			g_free(rd_search);

			if (l != NULL) {
				Win32SvcResolverData *rd = l->data;
				idata->resolvers = g_slist_delete_link(idata->resolvers, l);
				/* This IP is no longer available */
				if (rd->ip != NULL) {
					bb->ips = g_slist_remove(bb->ips, rd->ip);
					g_free((gchar *) rd->ip);
				}
				_cleanup_resolver_data(rd);

				/* If this was the last resolver, remove the buddy */
				if (idata->resolvers == NULL) {
					purple_debug_info("bonjour", "Removed last presence for buddy '%s'; signing off buddy.\n",
							  serviceName);
					bonjour_buddy_signed_off(pb);
				}
			}
		} else {
			purple_debug_warning("bonjour", "Unable to find buddy (%s) to remove\n", serviceName ? serviceName : "(null)");
			/* TODO: Should we look in the pending buddies list? */
		}
	}
}

/****************************
 * mdns_interface functions *
 ****************************/

gboolean _mdns_init_session(BonjourDnsSd *data) {
	data->mdns_impl_data = g_new0(Win32SessionImplData, 1);

	bonjour_dns_sd_set_jid(data->account, purple_get_host_name());

	return TRUE;
}

gboolean _mdns_publish(BonjourDnsSd *data, PublishType type, GSList *records) {
	TXTRecordRef dns_data;
	gboolean ret = TRUE;
	DNSServiceErrorType errorCode = kDNSServiceErr_NoError;
	Win32SessionImplData *idata = data->mdns_impl_data;

	g_return_val_if_fail(idata != NULL, FALSE);

	TXTRecordCreate(&dns_data, 256, NULL);

	while (records) {
		PurpleKeyValuePair *kvp = records->data;
		errorCode = TXTRecordSetValue(&dns_data, kvp->key, strlen(kvp->value), kvp->value);
		if (errorCode != kDNSServiceErr_NoError)
			break;
		records = records->next;
	}

	if (errorCode != kDNSServiceErr_NoError) {
		purple_debug_error("bonjour", "Unable to allocate memory for text record.(%d)\n", errorCode);
		ret = FALSE;
	} else {
		/* OK, we're done constructing the text record, (re)publish the service */
		DNSServiceRef presence_sr;

		switch (type) {
			case PUBLISH_START:
				purple_debug_info("bonjour", "Registering presence on port %d\n", data->port_p2pj);
				errorCode = DNSServiceRegister(&presence_sr, kDNSServiceInterfaceIndexAny,
					0, bonjour_get_jid(data->account), LINK_LOCAL_RECORD_NAME,
					NULL, NULL, htons(data->port_p2pj), TXTRecordGetLength(&dns_data), TXTRecordGetBytesPtr(&dns_data),
					_mdns_service_register_callback, NULL);
				break;

			case PUBLISH_UPDATE:
				purple_debug_info("bonjour", "Updating presence.\n");
				errorCode = DNSServiceUpdateRecord(idata->presence_query->sdRef, NULL, 0, TXTRecordGetLength(&dns_data), TXTRecordGetBytesPtr(&dns_data), 0);
				break;
		}

		if (errorCode != kDNSServiceErr_NoError) {
			purple_debug_error("bonjour", "Failed to publish presence service.(%d)\n", errorCode);
			ret = FALSE;
		} else if (type == PUBLISH_START) {
			/* We need to do this because according to the Apple docs:
			 * "the client is responsible for ensuring that DNSServiceProcessResult() is called
			 * whenever there is a reply from the daemon - the daemon may terminate its connection
			 * with a client that does not process the daemon's responses */
			idata->presence_query = g_new(DnsSDServiceRefHandlerData, 1);
			idata->presence_query->sdRef = presence_sr;
			idata->presence_query->account = data->account;
			idata->presence_query->input_handler = purple_input_add(DNSServiceRefSockFD(presence_sr),
				PURPLE_INPUT_READ, _mdns_handle_event, idata->presence_query);
		}
	}

	/* Free the memory used by temp data */
	TXTRecordDeallocate(&dns_data);
	return ret;
}

gboolean _mdns_browse(BonjourDnsSd *data) {
	DNSServiceErrorType errorCode;
	Win32SessionImplData *idata = data->mdns_impl_data;
	DNSServiceRef browser_sr;

	g_return_val_if_fail(idata != NULL, FALSE);

	errorCode = DNSServiceBrowse(&browser_sr, 0, kDNSServiceInterfaceIndexAny,
			LINK_LOCAL_RECORD_NAME, NULL,_mdns_service_browse_callback,
			data->account);
	if (errorCode == kDNSServiceErr_NoError) {
		idata->browser_query = g_new(DnsSDServiceRefHandlerData, 1);
		idata->browser_query->sdRef = browser_sr;
		idata->browser_query->account = data->account;
		idata->browser_query->input_handler = purple_input_add(DNSServiceRefSockFD(browser_sr),
			PURPLE_INPUT_READ, _mdns_handle_event, idata->browser_query);
		return TRUE;
	} else
		purple_debug_error("bonjour", "Error registering Local Link presence browser. (%d)\n", errorCode);


	return FALSE;
}

void _mdns_stop(BonjourDnsSd *data) {
	Win32SessionImplData *idata = data->mdns_impl_data;

	if (idata == NULL)
		return;

	if (idata->presence_query != NULL) {
		purple_input_remove(idata->presence_query->input_handler);
		DNSServiceRefDeallocate(idata->presence_query->sdRef);
		g_free(idata->presence_query);
	}

	if (idata->browser_query != NULL) {
		purple_input_remove(idata->browser_query->input_handler);
		DNSServiceRefDeallocate(idata->browser_query->sdRef);
		g_free(idata->browser_query);
	}

	g_free(idata);

	data->mdns_impl_data = NULL;
}

gboolean _mdns_set_buddy_icon_data(BonjourDnsSd *data, gconstpointer avatar_data, gsize avatar_len) {
	Win32SessionImplData *idata = data->mdns_impl_data;
	DNSServiceErrorType errorCode = kDNSServiceErr_NoError;

	g_return_val_if_fail(idata != NULL, FALSE);

	if (avatar_data != NULL && idata->buddy_icon_rec == NULL) {
		purple_debug_info("bonjour", "Setting new buddy icon.\n");
		errorCode = DNSServiceAddRecord(idata->presence_query->sdRef, &idata->buddy_icon_rec,
			0, kDNSServiceType_NULL, avatar_len, avatar_data, 0);
	} else if (avatar_data != NULL) {
		purple_debug_info("bonjour", "Updating existing buddy icon.\n");
		errorCode = DNSServiceUpdateRecord(idata->presence_query->sdRef, idata->buddy_icon_rec,
			0, avatar_len, avatar_data, 0);
	} else if (idata->buddy_icon_rec != NULL) {
		purple_debug_info("bonjour", "Removing existing buddy icon.\n");
		errorCode = DNSServiceRemoveRecord(idata->presence_query->sdRef, idata->buddy_icon_rec, 0);
		idata->buddy_icon_rec = NULL;
	}

	if (errorCode != kDNSServiceErr_NoError) {
		purple_debug_error("bonjour", "Error (%d) setting buddy icon record.\n", errorCode);
		return FALSE;
	}

	return TRUE;
}

void _mdns_init_buddy(BonjourBuddy *buddy) {
	buddy->mdns_impl_data = g_new0(Win32BuddyImplData, 1);
}

void _mdns_delete_buddy(BonjourBuddy *buddy) {
	Win32BuddyImplData *idata = buddy->mdns_impl_data;

	g_return_if_fail(idata != NULL);

	while (idata->resolvers) {
		Win32SvcResolverData *rd = idata->resolvers->data;
		_cleanup_resolver_data(rd);
		idata->resolvers = g_slist_delete_link(idata->resolvers, idata->resolvers);
	}

	if (idata->null_query != NULL) {
		purple_input_remove(idata->null_query->input_handler);
		DNSServiceRefDeallocate(idata->null_query->sdRef);
		g_free(idata->null_query);
	}

	g_free(idata);

	buddy->mdns_impl_data = NULL;
}

void _mdns_retrieve_buddy_icon(BonjourBuddy* buddy) {
	Win32BuddyImplData *idata = buddy->mdns_impl_data;
	char svc_name[kDNSServiceMaxDomainName];

	g_return_if_fail(idata != NULL);

	/* Cancel any existing query */
	if (idata->null_query != NULL) {
		purple_input_remove(idata->null_query->input_handler);
		DNSServiceRefDeallocate(idata->null_query->sdRef);
		g_free(idata->null_query);
		idata->null_query = NULL;
	}

	if (DNSServiceConstructFullName(svc_name, buddy->name, LINK_LOCAL_RECORD_NAME, "local") != 0)
		purple_debug_error("bonjour", "Unable to construct full name to retrieve buddy icon for %s.\n", buddy->name);
	else {
		DNSServiceRef null_query_sr;

		DNSServiceErrorType errorCode = DNSServiceQueryRecord(&null_query_sr, 0, kDNSServiceInterfaceIndexAny,
			svc_name, kDNSServiceType_NULL, kDNSServiceClass_IN, _mdns_record_query_callback, buddy);

		if (errorCode == kDNSServiceErr_NoError) {
			idata->null_query = g_new(DnsSDServiceRefHandlerData, 1);

			idata->null_query->sdRef = null_query_sr;
			idata->null_query->account = buddy->account;

			idata->null_query->input_handler = purple_input_add(DNSServiceRefSockFD(null_query_sr),
				PURPLE_INPUT_READ, _mdns_handle_event, idata->null_query);
		} else
			purple_debug_error("bonjour", "Unable to query buddy icon record for %s. (%d)\n", buddy->name, errorCode);
	}

}

