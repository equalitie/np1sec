/**
 * @file dnssrv.c
 */

/* purple
 *
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
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
 */
#define _PURPLE_DNSSRV_C_

#include "internal.h"
#include "util.h"

#ifndef _WIN32
#include <arpa/nameser.h>
#include <resolv.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#else /* WIN32 */
#include <windns.h>
/* Missing from the mingw headers */
#ifndef DNS_TYPE_SRV
# define DNS_TYPE_SRV PurpleDnsTypeSrv
#endif
#ifndef DNS_TYPE_TXT
# define DNS_TYPE_TXT PurpleDnsTypeTxt
#endif
#endif

#ifndef T_SRV
#define T_SRV	PurpleDnsTypeSrv
#endif
#ifndef T_TXT
#define T_TXT	PurpleDnsTypeTxt
#endif

#include "debug.h"
#include "dnssrv.h"
#include "eventloop.h"
#include "network.h"

static PurpleSrvTxtQueryUiOps *srv_txt_query_ui_ops = NULL;

#ifndef _WIN32
typedef union {
	HEADER hdr;
	u_char buf[1024];
} queryans;
#endif

struct _PurpleSrvTxtQueryData {
	union {
		PurpleSrvCallback srv;
		PurpleTxtCallback txt;
	} cb;

	gpointer extradata;
	guint handle;
	int type;
	char *query;
#ifdef _WIN32
	GThread *resolver;
	char *error_message;
	GList *results;
#else
	int fd_in, fd_out;
	pid_t pid;
#endif
};

typedef struct _PurpleSrvInternalQuery {
	int type;
	char query[256];
} PurpleSrvInternalQuery;

typedef struct _PurpleSrvResponseContainer {
	PurpleSrvResponse *response;
	int sum;
} PurpleSrvResponseContainer;

static gboolean purple_srv_txt_query_ui_resolve(PurpleSrvTxtQueryData *query_data);

/**
 * Sort by priority, then by weight.  Strictly numerically--no
 * randomness.  Technically we only need to sort by pref and then
 * make sure any records with weight 0 are at the beginning of
 * their group, but it's just as easy to sort by weight.
 */
static gint
responsecompare(gconstpointer ar, gconstpointer br)
{
	PurpleSrvResponse *a = (PurpleSrvResponse*)ar;
	PurpleSrvResponse *b = (PurpleSrvResponse*)br;

	if(a->pref == b->pref) {
		if(a->weight == b->weight)
			return 0;
		if(a->weight < b->weight)
			return -1;
		return 1;
	}
	if(a->pref < b->pref)
		return -1;
	return 1;
}

/**
 * Iterate over a list of PurpleSrvResponseContainer making the sum
 * the running total of the sums.  Select a random integer in the range
 * (1, sum+1), then find the first element greater than or equal to the
 * number selected.  From RFC 2782.
 *
 * @param list The list of PurpleSrvResponseContainer.  This function
 *        removes a node from this list and returns the new list.
 * @param container_ptr The PurpleSrvResponseContainer that was chosen
 *        will be returned here.
 */
static GList *
select_random_response(GList *list, PurpleSrvResponseContainer **container_ptr)
{
	GList *cur;
	size_t runningtotal;
	int r;

	runningtotal = 0;
	cur = list;

	while (cur) {
		PurpleSrvResponseContainer *container = cur->data;
		runningtotal += container->response->weight;
		container->sum = runningtotal;
		cur = cur->next;
	}

	/*
	 * If the running total is greater than 0, pick a number between
	 * 1 and the runningtotal inclusive. (This is not precisely what
	 * the RFC algorithm describes, but we wish to deal with integers
	 * and avoid floats.  This is functionally equivalent.)
	 * If running total is 0, then choose r = 0.
	 */
	r = runningtotal ? g_random_int_range(1, runningtotal + 1) : 0;
	cur = list;
	while (r > ((PurpleSrvResponseContainer *)cur->data)->sum) {
		cur = cur->next;
	}

	/* Set the return parameter and remove cur from the list */
	*container_ptr =  cur->data;
	return g_list_delete_link(list, cur);
}

/**
 * Reorder a GList of PurpleSrvResponses that have the same priority
 * (aka "pref").
 */
static void
srv_reorder(GList *list, int num)
{
	int i;
	GList *cur, *container_list = NULL;
	PurpleSrvResponseContainer *container;

	if (num < 2)
		/* Nothing to sort */
		return;

	/* First build a list of container structs */
	for (i = 0, cur = list; i < num; i++, cur = cur->next) {
		container = g_new(PurpleSrvResponseContainer, 1);
		container->response = cur->data;
		container_list = g_list_prepend(container_list, container);
	}
	container_list = g_list_reverse(container_list);

	/*
	 * Re-order the list that was passed in as a parameter.  We leave
	 * the list nodes in place, but replace their data pointers.
	 */
	cur = list;
	while (container_list) {
		container_list = select_random_response(container_list, &container);
		cur->data = container->response;
		g_free(container);
		cur = cur->next;
	}
}

/**
 * Sorts a GList of PurpleSrvResponses according to the
 * algorithm described in RFC 2782.
 *
 * @param response GList of PurpleSrvResponse's
 * @param The original list, resorted
 */
static GList *
purple_srv_sort(GList *list)
{
	int pref, count;
	GList *cur, *start;

	if (!list || !list->next) {
		/* Nothing to sort */
		return list;
	}

	list = g_list_sort(list, responsecompare);

	start = cur = list;
	count = 1;
	while (cur) {
		PurpleSrvResponse *next_response;
		pref = ((PurpleSrvResponse *)cur->data)->pref;
		next_response = cur->next ? cur->next->data : NULL;
		if (!next_response || next_response->pref != pref) {
			/*
			 * The 'count' records starting at 'start' all have the same
			 * priority.  Sort them by weight.
			 */
			srv_reorder(start, count);
			start = cur->next;
			count = 0;
		}
		count++;
		cur = cur->next;
	}

	return list;
}

static PurpleSrvTxtQueryData *
query_data_new(int type, gchar *query, gpointer extradata)
{
	PurpleSrvTxtQueryData *query_data = g_new0(PurpleSrvTxtQueryData, 1);
	query_data->type = type;
	query_data->extradata = extradata;
	query_data->query = query;
#ifndef _WIN32
	query_data->fd_in = -1;
	query_data->fd_out = -1;
#endif
	return query_data;
}

void
purple_srv_txt_query_destroy(PurpleSrvTxtQueryData *query_data)
{
	PurpleSrvTxtQueryUiOps *ops = purple_srv_txt_query_get_ui_ops();

	if (ops && ops->destroy)
		ops->destroy(query_data);

	if (query_data->handle > 0)
		purple_input_remove(query_data->handle);
#ifdef _WIN32
	if (query_data->resolver != NULL)
	{
		/*
		 * It's not really possible to kill a thread.  So instead we
		 * just set the callback to NULL and let the DNS lookup
		 * finish.
		 */
		query_data->cb.srv = NULL;
		return;
	}
	g_free(query_data->error_message);
#else
	if (query_data->fd_out != -1)
		close(query_data->fd_out);
	if (query_data->fd_in != -1)
		close(query_data->fd_in);
#endif
	g_free(query_data->query);
	g_free(query_data);
}

#ifdef USE_IDN
static gboolean
dns_str_is_ascii(const char *name)
{
	guchar *c;
	for (c = (guchar *)name; c && *c; ++c) {
		if (*c > 0x7f)
			return FALSE;
	}

	return TRUE;
}
#endif

#ifndef _WIN32
static void
write_to_parent(int in, int out, gconstpointer data, gsize size)
{
	const guchar *buf = data;
	gssize w;

	do {
		w = write(out, buf, size);
		if (w > 0) {
			buf += w;
			size -= w;
		} else if (w < 0 && errno == EINTR) {
			/* Let's try some more; */
			w = 1;
		}
	} while (size > 0 && w > 0);

	if (size != 0) {
		/* An error occurred */
		close(out);
		close(in);
		_exit(0);
	}
}

/* Read size bytes to data. Dies if an error occurs. */
static void
read_from_parent(int in, int out, gpointer data, gsize size)
{
	guchar *buf = data;
	gssize r;

	do {
		r = read(in, data, size);
		if (r > 0) {
			buf += r;
			size -= r;
		} else if (r < 0 && errno == EINTR) {
			/* Let's try some more; */
			r = 1;
		}
	} while (size > 0 && r > 0);

	if (size != 0) {
		/* An error occurred */
		close(out);
		close(in);
		_exit(0);
	}
}


G_GNUC_NORETURN static void
resolve(int in, int out)
{
	GList *ret = NULL;
	PurpleSrvResponse *srvres;
	PurpleTxtResponse *txtres;
	queryans answer;
	int size, qdcount, ancount;
	guchar *end, *cp;
	gchar name[256];
	guint16 type, dlen, pref, weight, port;
	PurpleSrvInternalQuery query;

#ifdef HAVE_SIGNAL_H
	purple_restore_default_signal_handlers();
#endif

	read_from_parent(in, out, &query, sizeof(query));

	size = res_query( query.query, C_IN, query.type, (u_char*)&answer, sizeof( answer));
	if (size == -1) {
		write_to_parent(in, out, &(query.type), sizeof(query.type));
		write_to_parent(in, out, &size, sizeof(size));
		close(out);
		close(in);
		_exit(0);
	}

	qdcount = ntohs(answer.hdr.qdcount);
	ancount = ntohs(answer.hdr.ancount);
	cp = (guchar*)&answer + sizeof(HEADER);
	end = (guchar*)&answer + size;

	/* skip over unwanted stuff */
	while (qdcount-- > 0 && cp < end) {
		size = dn_expand( (unsigned char*)&answer, end, cp, name, 256);
		if(size < 0) goto end;
		cp += size + QFIXEDSZ;
	}

	while (ancount-- > 0 && cp < end) {
		size = dn_expand((unsigned char*)&answer, end, cp, name, 256);
		if(size < 0)
			goto end;
		cp += size;
		GETSHORT(type,cp);

		/* skip ttl and class since we already know it */
		cp += 6;

		GETSHORT(dlen,cp);
		if (type == T_SRV) {
			GETSHORT(pref,cp);

			GETSHORT(weight,cp);

			GETSHORT(port,cp);

			size = dn_expand( (unsigned char*)&answer, end, cp, name, 256);
			if(size < 0 )
				goto end;

			cp += size;

			srvres = g_new0(PurpleSrvResponse, 1);
			if (strlen(name) > sizeof(srvres->hostname) - 1) {
				purple_debug_error("dnssrv", "hostname is longer than available buffer ('%s', %zd bytes)!",
				                   name, strlen(name));
			}
			g_strlcpy(srvres->hostname, name, sizeof(srvres->hostname));
			srvres->pref = pref;
			srvres->port = port;
			srvres->weight = weight;

			ret = g_list_prepend(ret, srvres);
		} else if (type == T_TXT) {
			txtres = g_new0(PurpleTxtResponse, 1);
			txtres->content = g_strndup((gchar*)(++cp), dlen-1);
			ret = g_list_append(ret, txtres);
			cp += dlen - 1;
		} else {
			cp += dlen;
		}
	}

end:
	size = g_list_length(ret);

	if (query.type == T_SRV)
		ret = purple_srv_sort(ret);

	write_to_parent(in, out, &(query.type), sizeof(query.type));
	write_to_parent(in, out, &size, sizeof(size));
	while (ret != NULL)
	{
		if (query.type == T_SRV)
			write_to_parent(in, out, ret->data, sizeof(PurpleSrvResponse));
		if (query.type == T_TXT) {
			PurpleTxtResponse *response = ret->data;
			gsize l = strlen(response->content) + 1 /* null byte */;
			write_to_parent(in, out, &l, sizeof(l));
			write_to_parent(in, out, response->content, l);
		}

		g_free(ret->data);
		ret = g_list_remove(ret, ret->data);
	}

	close(out);
	close(in);

	_exit(0);
}

static void
resolved(gpointer data, gint source, PurpleInputCondition cond)
{
	int size;
	int type;
	PurpleSrvTxtQueryData *query_data = (PurpleSrvTxtQueryData*)data;
	int i;
	int status;

	if (read(source, &type, sizeof(type)) == sizeof(type)) {
		if (read(source, &size, sizeof(size)) == sizeof(size)) {
			if (size == -1 || size == 0) {
				if (size == -1) {
					purple_debug_warning("dnssrv", "res_query returned an error\n");
					/* Re-read resolv.conf and friends in case DNS servers have changed */
					res_init();
				} else
					purple_debug_info("dnssrv", "Found 0 entries, errno is %i\n", errno);

				if (type == T_SRV) {
					PurpleSrvCallback cb = query_data->cb.srv;
					cb(NULL, 0, query_data->extradata);
				} else if (type == T_TXT) {
					PurpleTxtCallback cb = query_data->cb.txt;
					cb(NULL, query_data->extradata);
				} else {
					purple_debug_error("dnssrv", "type unknown of DNS result entry; errno is %i\n", errno);
				}

			} else if (size) {
				if (type == T_SRV) {
					PurpleSrvResponse *res;
					PurpleSrvResponse *tmp;
					PurpleSrvCallback cb = query_data->cb.srv;
					ssize_t red;
					purple_debug_info("dnssrv","found %d SRV entries\n", size);
					tmp = res = g_new0(PurpleSrvResponse, size);
					for (i = 0; i < size; i++) {
						red = read(source, tmp++, sizeof(PurpleSrvResponse));
						if (red != sizeof(PurpleSrvResponse)) {
							purple_debug_error("dnssrv","unable to read srv "
									"response: %s\n", g_strerror(errno));
							size = 0;
							g_free(res);
							res = NULL;
						}
					}

					cb(res, size, query_data->extradata);
				} else if (type == T_TXT) {
					GList *responses = NULL;
					PurpleTxtResponse *res;
					PurpleTxtCallback cb = query_data->cb.txt;
					ssize_t red;
					purple_debug_info("dnssrv","found %d TXT entries\n", size);
					for (i = 0; i < size; i++) {
						gsize len;

						red = read(source, &len, sizeof(len));
						if (red != sizeof(len)) {
							purple_debug_error("dnssrv","unable to read txt "
									"response length: %s\n", g_strerror(errno));
							size = 0;
							g_list_foreach(responses, (GFunc)purple_txt_response_destroy, NULL);
							g_list_free(responses);
							responses = NULL;
							break;
						}

						res = g_new0(PurpleTxtResponse, 1);
						res->content = g_new0(gchar, len);

						red = read(source, res->content, len);
						if (red != len) {
							purple_debug_error("dnssrv","unable to read txt "
									"response: %s\n", g_strerror(errno));
							size = 0;
							purple_txt_response_destroy(res);
							g_list_foreach(responses, (GFunc)purple_txt_response_destroy, NULL);
							g_list_free(responses);
							responses = NULL;
							break;
						}
						responses = g_list_prepend(responses, res);
					}

					responses = g_list_reverse(responses);
					cb(responses, query_data->extradata);
				} else {
					purple_debug_error("dnssrv", "type unknown of DNS result entry; errno is %i\n", errno);
				}
			}
		}
	}

	waitpid(query_data->pid, &status, 0);
	purple_srv_txt_query_destroy(query_data);
}

#else /* _WIN32 */

/** The Jabber Server code was inspiration for parts of this. */

static gboolean
res_main_thread_cb(gpointer data)
{
	PurpleSrvResponse *srvres = NULL;
	PurpleSrvTxtQueryData *query_data = data;
	if(query_data->error_message != NULL) {
		purple_debug_error("dnssrv", "%s", query_data->error_message);
		if (query_data->type == DNS_TYPE_SRV) {
			if (query_data->cb.srv)
				query_data->cb.srv(srvres, 0, query_data->extradata);
		} else if (query_data->type == DNS_TYPE_TXT) {
			if (query_data->cb.txt)
				query_data->cb.txt(NULL, query_data->extradata);
		}
	} else {
		if (query_data->type == DNS_TYPE_SRV) {
			PurpleSrvResponse *srvres_tmp = NULL;
			GList *lst = query_data->results;
			int size = g_list_length(lst);

			if(query_data->cb.srv && size > 0)
				srvres_tmp = srvres = g_new0(PurpleSrvResponse, size);
			while (lst) {
				PurpleSrvResponse *lstdata = lst->data;
				lst = g_list_delete_link(lst, lst);

				if(query_data->cb.srv)
					memcpy(srvres_tmp++, lstdata, sizeof(PurpleSrvResponse));
				g_free(lstdata);
			}

			query_data->results = NULL;

			purple_debug_info("dnssrv", "found %d SRV entries\n", size);

			if(query_data->cb.srv) query_data->cb.srv(srvres, size, query_data->extradata);
		} else if (query_data->type == DNS_TYPE_TXT) {
			GList *lst = query_data->results;

			purple_debug_info("dnssrv", "found %d TXT entries\n", g_list_length(lst));

			if (query_data->cb.txt) {
				query_data->results = NULL;
				query_data->cb.txt(lst, query_data->extradata);
			}
		} else {
			purple_debug_error("dnssrv", "unknown query type");
		}
	}

	query_data->resolver = NULL;
	query_data->handle = 0;

	purple_srv_txt_query_destroy(query_data);

	return FALSE;
}

static gpointer
res_thread(gpointer data)
{
	PDNS_RECORD dr = NULL;
	int type;
	DNS_STATUS ds;
	PurpleSrvTxtQueryData *query_data = data;
	type = query_data->type;
	ds = DnsQuery_UTF8(query_data->query, type, DNS_QUERY_STANDARD, NULL, &dr, NULL);
	if (ds != ERROR_SUCCESS) {
		gchar *msg = g_win32_error_message(ds);
		if (type == DNS_TYPE_SRV) {
			query_data->error_message = g_strdup_printf("Couldn't look up SRV record. %s (%lu).\n", msg, ds);
		} else if (type == DNS_TYPE_TXT) {
			query_data->error_message = g_strdup_printf("Couldn't look up TXT record. %s (%lu).\n", msg, ds);
		}
		g_free(msg);
	} else {
		if (type == DNS_TYPE_SRV) {
			PDNS_RECORD dr_tmp;
			GList *lst = NULL;
			DNS_SRV_DATA *srv_data;
			PurpleSrvResponse *srvres;

			for (dr_tmp = dr; dr_tmp != NULL; dr_tmp = dr_tmp->pNext) {
				/* Discard any incorrect entries. I'm not sure if this is necessary */
				if (dr_tmp->wType != type || strcmp(dr_tmp->pName, query_data->query) != 0) {
					continue;
				}

				srv_data = &dr_tmp->Data.SRV;
				srvres = g_new0(PurpleSrvResponse, 1);
				strncpy(srvres->hostname, srv_data->pNameTarget, 255);
				srvres->hostname[255] = '\0';
				srvres->pref = srv_data->wPriority;
				srvres->port = srv_data->wPort;
				srvres->weight = srv_data->wWeight;

				lst = g_list_prepend(lst, srvres);
			}

			DnsRecordListFree(dr, DnsFreeRecordList);
			query_data->results = purple_srv_sort(lst);
		} else if (type == DNS_TYPE_TXT) {
			PDNS_RECORD dr_tmp;
			GList *lst = NULL;
			DNS_TXT_DATA *txt_data;
			PurpleTxtResponse *txtres;

			for (dr_tmp = dr; dr_tmp != NULL; dr_tmp = dr_tmp->pNext) {
				GString *s;
				int i;

				/* Discard any incorrect entries. I'm not sure if this is necessary */
				if (dr_tmp->wType != type || strcmp(dr_tmp->pName, query_data->query) != 0) {
					continue;
				}

				txt_data = &dr_tmp->Data.TXT;
				txtres = g_new0(PurpleTxtResponse, 1);

				s = g_string_new("");
				for (i = 0; i < txt_data->dwStringCount; ++i)
					s = g_string_append(s, txt_data->pStringArray[i]);
				txtres->content = g_string_free(s, FALSE);

				lst = g_list_append(lst, txtres);
			}

			DnsRecordListFree(dr, DnsFreeRecordList);
			query_data->results = lst;
		} else {

		}
	}

	/* back to main thread */
	/* Note: this should *not* be attached to query_data->handle - it will cause leakage */
	purple_timeout_add(0, res_main_thread_cb, query_data);

	g_thread_exit(NULL);
	return NULL;
}

#endif

PurpleSrvTxtQueryData *
purple_srv_resolve(const char *protocol, const char *transport,
	const char *domain, PurpleSrvCallback cb, gpointer extradata)
{
	return purple_srv_resolve_account(NULL, protocol, transport, domain,
			cb, extradata);
}

PurpleSrvTxtQueryData *
purple_srv_resolve_account(PurpleAccount *account, const char *protocol,
	const char *transport, const char *domain, PurpleSrvCallback cb,
	gpointer extradata)
{
	char *query;
	char *hostname;
	PurpleSrvTxtQueryData *query_data;
	PurpleProxyType proxy_type;
#ifndef _WIN32
	PurpleSrvInternalQuery internal_query;
	int in[2], out[2];
	int pid;
#else
	GError* err = NULL;
#endif

	if (!protocol || !*protocol || !transport || !*transport || !domain || !*domain) {
		purple_debug_error("dnssrv", "Wrong arguments\n");
		cb(NULL, 0, extradata);
		g_return_val_if_reached(NULL);
	}

	proxy_type = purple_proxy_info_get_type(
		purple_proxy_get_setup(account));
	if (proxy_type == PURPLE_PROXY_TOR) {
		purple_debug_info("dnssrv", "Aborting SRV lookup in Tor Proxy mode.");
		cb(NULL, 0, extradata);
		return NULL;
	}

#ifdef USE_IDN
	if (!dns_str_is_ascii(domain)) {
		int ret = purple_network_convert_idn_to_ascii(domain, &hostname);
		if (ret != 0) {
			purple_debug_error("dnssrv", "IDNA ToASCII failed\n");
			cb(NULL, 0, extradata);
			return NULL;
		}
	} else /* Fallthru is intentional */
#endif
	hostname = g_strdup(domain);

	query = g_strdup_printf("_%s._%s.%s", protocol, transport, hostname);
	purple_debug_info("dnssrv","querying SRV record for %s: %s\n", domain,
			query);
	g_free(hostname);

	query_data = query_data_new(PurpleDnsTypeSrv, query, extradata);
	query_data->cb.srv = cb;

	if (purple_srv_txt_query_ui_resolve(query_data))
	{
		return query_data;
	}

#ifndef _WIN32
	if(pipe(in) || pipe(out)) {
		purple_debug_error("dnssrv", "Could not create pipe\n");
		g_free(query);
		g_free(query_data);
		cb(NULL, 0, extradata);
		return NULL;
	}

	pid = fork();
	if (pid == -1) {
		purple_debug_error("dnssrv", "Could not create process!\n");
		g_free(query);
		g_free(query_data);
		cb(NULL, 0, extradata);
		return NULL;
	}

	/* Child */
	if (pid == 0)
	{
		g_free(query);
		g_free(query_data);

		close(out[0]);
		close(in[1]);
		resolve(in[0], out[1]);
		/* resolve() does not return */
	}

	close(out[1]);
	close(in[0]);

	internal_query.type = T_SRV;
	strncpy(internal_query.query, query, 255);
	internal_query.query[255] = '\0';

	if (write(in[1], &internal_query, sizeof(internal_query)) < 0)
		purple_debug_error("dnssrv", "Could not write to SRV resolver\n");

	query_data->pid = pid;
	query_data->fd_out = out[0];
	query_data->fd_in = in[1];
	query_data->handle = purple_input_add(out[0], PURPLE_INPUT_READ, resolved, query_data);

	return query_data;
#else
	query_data->resolver = g_thread_create(res_thread, query_data, FALSE, &err);
	if (query_data->resolver == NULL) {
		query_data->error_message = g_strdup_printf("SRV thread create failure: %s\n", (err && err->message) ? err->message : "");
		g_error_free(err);
	}

	/* The query isn't going to happen, so finish the SRV lookup now.
	 * Asynchronously call the callback since stuff may not expect
	 * the callback to be called before this returns */
	if (query_data->error_message != NULL)
		query_data->handle = purple_timeout_add(0, res_main_thread_cb, query_data);

	return query_data;
#endif
}

PurpleSrvTxtQueryData *purple_txt_resolve(const char *owner,
	const char *domain, PurpleTxtCallback cb, gpointer extradata)
{
	return purple_txt_resolve_account(NULL, owner, domain, cb, extradata);
}

PurpleSrvTxtQueryData *purple_txt_resolve_account(PurpleAccount *account,
	const char *owner, const char *domain, PurpleTxtCallback cb,
	gpointer extradata)
{
	char *query;
	char *hostname;
	PurpleSrvTxtQueryData *query_data;
	PurpleProxyType proxy_type;
#ifndef _WIN32
	PurpleSrvInternalQuery internal_query;
	int in[2], out[2];
	int pid;
#else
	GError* err = NULL;
#endif

	proxy_type = purple_proxy_info_get_type(
		purple_proxy_get_setup(account));
	if (proxy_type == PURPLE_PROXY_TOR) {
		purple_debug_info("dnssrv", "Aborting TXT lookup in Tor Proxy mode.");
		cb(NULL, extradata);
		return NULL;
	}

#ifdef USE_IDN
	if (!dns_str_is_ascii(domain)) {
		int ret = purple_network_convert_idn_to_ascii(domain, &hostname);
		if (ret != 0) {
			purple_debug_error("dnssrv", "IDNA ToASCII failed\n");
			cb(NULL, extradata);
			return NULL;
		}
	} else /* fallthru is intentional */
#endif
	hostname = g_strdup(domain);

	query = g_strdup_printf("%s.%s", owner, hostname);
	purple_debug_info("dnssrv","querying TXT record for %s: %s\n", domain,
			query);
	g_free(hostname);

	query_data = query_data_new(PurpleDnsTypeTxt, query, extradata);
	query_data->cb.txt = cb;

	if (purple_srv_txt_query_ui_resolve(query_data)) {
		/* query intentionally not freed
		 */
		return query_data;
	}

#ifndef _WIN32
	if(pipe(in) || pipe(out)) {
		purple_debug_error("dnssrv", "Could not create pipe\n");
		g_free(query);
		g_free(query_data);
		cb(NULL, extradata);
		return NULL;
	}

	pid = fork();
	if (pid == -1) {
		purple_debug_error("dnssrv", "Could not create process!\n");
		g_free(query);
		g_free(query_data);
		cb(NULL, extradata);
		return NULL;
	}

	/* Child */
	if (pid == 0)
	{
		g_free(query);
		g_free(query_data);

		close(out[0]);
		close(in[1]);
		resolve(in[0], out[1]);
		/* resolve() does not return */
	}

	close(out[1]);
	close(in[0]);

	internal_query.type = T_TXT;
	strncpy(internal_query.query, query, 255);
	internal_query.query[255] = '\0';

	if (write(in[1], &internal_query, sizeof(internal_query)) < 0)
		purple_debug_error("dnssrv", "Could not write to TXT resolver\n");

	query_data->pid = pid;
	query_data->fd_out = out[0];
	query_data->fd_in = in[1];
	query_data->handle = purple_input_add(out[0], PURPLE_INPUT_READ, resolved, query_data);

	return query_data;
#else
	query_data->resolver = g_thread_create(res_thread, query_data, FALSE, &err);
	if (query_data->resolver == NULL) {
		query_data->error_message = g_strdup_printf("TXT thread create failure: %s\n", (err && err->message) ? err->message : "");
		g_error_free(err);
	}

	/* The query isn't going to happen, so finish the TXT lookup now.
	 * Asynchronously call the callback since stuff may not expect
	 * the callback to be called before this returns */
	if (query_data->error_message != NULL)
		query_data->handle = purple_timeout_add(0, res_main_thread_cb, query_data);

	return query_data;
#endif
}

void
purple_txt_cancel(PurpleSrvTxtQueryData *query_data)
{
	purple_srv_txt_query_destroy(query_data);
}

void
purple_srv_cancel(PurpleSrvTxtQueryData *query_data)
{
	purple_srv_txt_query_destroy(query_data);
}

const gchar *
purple_txt_response_get_content(PurpleTxtResponse *resp)
{
	g_return_val_if_fail(resp != NULL, NULL);

	return resp->content;
}

void purple_txt_response_destroy(PurpleTxtResponse *resp)
{
	g_return_if_fail(resp != NULL);

	g_free(resp->content);
	g_free(resp);
}

/*
 * Only used as the callback for the ui ops.
 */
static void
purple_srv_query_resolved(PurpleSrvTxtQueryData *query_data, GList *records)
{
	GList *l;
	PurpleSrvResponse *records_array;
	int i = 0, length;

	g_return_if_fail(records != NULL);

	if (query_data->cb.srv == NULL) {
		purple_srv_txt_query_destroy(query_data);

		while (records) {
			g_free(records->data);
			records = g_list_delete_link(records, records);
		}
		return;
	}

	records = purple_srv_sort(records);
	length = g_list_length(records);

	purple_debug_info("dnssrv", "SRV records resolved for %s, count: %d\n",
	                            query_data->query, length);

	records_array = g_new(PurpleSrvResponse, length);
	for (l = records; l; l = l->next, i++) {
		records_array[i] = *(PurpleSrvResponse *)l->data;
	}

	query_data->cb.srv(records_array, length, query_data->extradata);

	purple_srv_txt_query_destroy(query_data);

	while (records) {
		g_free(records->data);
		records = g_list_delete_link(records, records);
	}
}

/*
 * Only used as the callback for the ui ops.
 */
static void
purple_txt_query_resolved(PurpleSrvTxtQueryData *query_data, GList *entries)
{
	g_return_if_fail(entries != NULL);

	purple_debug_info("dnssrv", "TXT entries resolved for %s, count: %d\n", query_data->query, g_list_length(entries));

	/* the callback should g_free the entries.
	 */
	if (query_data->cb.txt != NULL)
		query_data->cb.txt(entries, query_data->extradata);
	else {
		while (entries) {
			g_free(entries->data);
			entries = g_list_delete_link(entries, entries);
		}
	}

	purple_srv_txt_query_destroy(query_data);
}

static void
purple_srv_query_failed(PurpleSrvTxtQueryData *query_data, const gchar *error_message)
{
	purple_debug_error("dnssrv", "%s\n", error_message);

	if (query_data->cb.srv != NULL)
		query_data->cb.srv(NULL, 0, query_data->extradata);

	purple_srv_txt_query_destroy(query_data);
}

static gboolean
purple_srv_txt_query_ui_resolve(PurpleSrvTxtQueryData *query_data)
{
	PurpleSrvTxtQueryUiOps *ops = purple_srv_txt_query_get_ui_ops();

	if (ops && ops->resolve)
		return ops->resolve(query_data, (query_data->type == T_SRV ? purple_srv_query_resolved : purple_txt_query_resolved), purple_srv_query_failed);

	return FALSE;
}

void
purple_srv_txt_query_set_ui_ops(PurpleSrvTxtQueryUiOps *ops)
{
	srv_txt_query_ui_ops = ops;
}

PurpleSrvTxtQueryUiOps *
purple_srv_txt_query_get_ui_ops(void)
{
	/* It is perfectly acceptable for srv_txt_query_ui_ops to be NULL; this just
	 * means that the default platform-specific implementation will be used.
	 */
	return srv_txt_query_ui_ops;
}

char *
purple_srv_txt_query_get_query(PurpleSrvTxtQueryData *query_data)
{
	g_return_val_if_fail(query_data != NULL, NULL);

	return query_data->query;
}


int
purple_srv_txt_query_get_type(PurpleSrvTxtQueryData *query_data)
{
	g_return_val_if_fail(query_data != NULL, 0);

	return query_data->type;
}
