/**
 * @file dnsquery.c DNS query API
 * @ingroup core
 */

/* purple
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
#define _PURPLE_DNSQUERY_C_

#include "internal.h"
#include "debug.h"
#include "dnsquery.h"
#include "network.h"
#include "notify.h"
#include "prefs.h"
#include "util.h"

#ifndef _WIN32
#include <resolv.h>
#endif

#if (defined(__APPLE__) || defined (__unix__)) && !defined(__osf__)
#define PURPLE_DNSQUERY_USE_FORK
#endif
/**************************************************************************
 * DNS query API
 **************************************************************************/

static PurpleDnsQueryUiOps *dns_query_ui_ops = NULL;

typedef struct _PurpleDnsQueryResolverProcess PurpleDnsQueryResolverProcess;

struct _PurpleDnsQueryData {
	char *hostname;
	int port;
	PurpleDnsQueryConnectFunction callback;
	gpointer data;
	guint timeout;
	PurpleAccount *account;

#if defined(PURPLE_DNSQUERY_USE_FORK)
	PurpleDnsQueryResolverProcess *resolver;
#elif defined _WIN32 /* end PURPLE_DNSQUERY_USE_FORK  */
	GThread *resolver;
	GSList *hosts;
	gchar *error_message;
#endif
};

#if defined(PURPLE_DNSQUERY_USE_FORK)

#define MAX_DNS_CHILDREN 4

/*
 * This structure keeps a reference to a child resolver process.
 */
struct _PurpleDnsQueryResolverProcess {
	guint inpa;
	int fd_in, fd_out;
	pid_t dns_pid;
};

static GSList *free_dns_children = NULL;
/* TODO: Make me a GQueue when we require >= glib 2.4 */
static GSList *queued_requests = NULL;

static int number_of_dns_children = 0;

/*
 * This is a convenience struct used to pass data to
 * the child resolver process.
 */
typedef struct {
	char hostname[512];
	int port;
} dns_params_t;
#endif /* end PURPLE_DNSQUERY_USE_FORK */

static void
purple_dnsquery_resolved(PurpleDnsQueryData *query_data, GSList *hosts)
{
	purple_debug_info("dnsquery", "IP resolved for %s\n", query_data->hostname);
	if (query_data->callback != NULL)
		query_data->callback(hosts, query_data->data, NULL);
	else
	{
		/*
		 * Callback is a required parameter, but it can get set to
		 * NULL if we cancel a thread-based DNS lookup.  So we need
		 * to free hosts.
		 */
		while (hosts != NULL)
		{
			hosts = g_slist_remove(hosts, hosts->data);
			g_free(hosts->data);
			hosts = g_slist_remove(hosts, hosts->data);
		}
	}

#ifdef PURPLE_DNSQUERY_USE_FORK
	/*
	 * Add the resolver to the list of available resolvers, and set it
	 * to NULL so that it doesn't get destroyed along with the query_data
	 */
	if (query_data->resolver)
	{
		free_dns_children = g_slist_prepend(free_dns_children, query_data->resolver);
		query_data->resolver = NULL;
	}
#endif /* PURPLE_DNSQUERY_USE_FORK */

	purple_dnsquery_destroy(query_data);
}

static void
purple_dnsquery_failed(PurpleDnsQueryData *query_data, const gchar *error_message)
{
	purple_debug_error("dnsquery", "%s\n", error_message);
	if (query_data->callback != NULL)
		query_data->callback(NULL, query_data->data, error_message);
	purple_dnsquery_destroy(query_data);
}

static gboolean
purple_dnsquery_ui_resolve(PurpleDnsQueryData *query_data)
{
	PurpleDnsQueryUiOps *ops = purple_dnsquery_get_ui_ops();

	if (ops && ops->resolve_host)
		return ops->resolve_host(query_data, purple_dnsquery_resolved, purple_dnsquery_failed);

	return FALSE;
}

static gboolean
resolve_ip(PurpleDnsQueryData *query_data)
{
#if defined(HAVE_GETADDRINFO) && defined(AI_NUMERICHOST)
	struct addrinfo hints, *res;
	char servname[20];

	g_snprintf(servname, sizeof(servname), "%d", query_data->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags |= AI_NUMERICHOST;

	if (0 == getaddrinfo(query_data->hostname, servname, &hints, &res))
	{
		GSList *hosts = NULL;
		hosts = g_slist_append(hosts, GINT_TO_POINTER(res->ai_addrlen));
		hosts = g_slist_append(hosts, g_memdup(res->ai_addr, res->ai_addrlen));
		purple_dnsquery_resolved(query_data, hosts);

		freeaddrinfo(res);
		return TRUE;
	}
#else /* defined(HAVE_GETADDRINFO) && defined(AI_NUMERICHOST) */
	struct sockaddr_in sin;
	if (inet_aton(query_data->hostname, &sin.sin_addr))
	{
		/*
		 * The given "hostname" is actually an IP address, so we
		 * don't need to do anything.
		 */
		GSList *hosts = NULL;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(query_data->port);
		hosts = g_slist_append(hosts, GINT_TO_POINTER(sizeof(sin)));
		hosts = g_slist_append(hosts, g_memdup(&sin, sizeof(sin)));
		purple_dnsquery_resolved(query_data, hosts);

		return TRUE;
	}
#endif

	return FALSE;
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

#if defined(PURPLE_DNSQUERY_USE_FORK)

/*
 * Unix!
 */

/*
 * Begin the DNS resolver child process functions.
 */
#ifdef HAVE_SIGNAL_H
G_GNUC_NORETURN static void
trap_gdb_bug(int sig)
{
	const char *message =
		"Purple's DNS child got a SIGTRAP signal.\n"
		"This can be caused by trying to run purple inside gdb.\n"
		"There is a known gdb bug which prevents this.  Supposedly purple\n"
		"should have detected you were using gdb and used an ugly hack,\n"
		"check cope_with_gdb_brokenness() in dnsquery.c.\n\n"
		"For more info about this bug, see http://sources.redhat.com/ml/gdb/2001-07/msg00349.html\n";
	fputs("\n* * *\n",stderr);
	fputs(message,stderr);
	fputs("* * *\n\n",stderr);
	execlp("xmessage","xmessage","-center", message, NULL);
	_exit(1);
}
#endif

static void
write_to_parent(int fd, const void *buf, size_t count)
{
	ssize_t written;

	written = write(fd, buf, count);
	if (written != count) {
		if (written < 0)
			fprintf(stderr, "dns[%d]: Error writing data to "
					"parent: %s\n", getpid(), strerror(errno));
		else
			fprintf(stderr, "dns[%d]: Error: Tried to write %"
					G_GSIZE_FORMAT " bytes to parent but instead "
					"wrote %" G_GSIZE_FORMAT " bytes\n",
					getpid(), count, written);
	}
}

G_GNUC_NORETURN static void
purple_dnsquery_resolver_run(int child_out, int child_in, gboolean show_debug)
{
	dns_params_t dns_params;
	const size_t zero = 0;
	int rc;
#ifdef HAVE_GETADDRINFO
	struct addrinfo hints, *res, *tmp;
	char servname[20];
#else
	struct sockaddr_in sin;
	const size_t addrlen = sizeof(sin);
#endif
	char *hostname;

#ifdef HAVE_SIGNAL_H
	purple_restore_default_signal_handlers();
	signal(SIGTRAP, trap_gdb_bug);
#endif

	/*
	 * We resolve 1 host name for each iteration of this
	 * while loop.
	 *
	 * The top half of this reads in the hostname and port
	 * number from the socket with our parent.  The bottom
	 * half of this resolves the IP (blocking) and sends
	 * the result back to our parent, when finished.
	 */
	while (1) {
		fd_set fds;
		struct timeval tv = { .tv_sec = 20, .tv_usec = 0 };
		FD_ZERO(&fds);
		FD_SET(child_in, &fds);
		rc = select(child_in + 1, &fds, NULL, NULL, &tv);
		if (!rc) {
			if (show_debug)
				printf("dns[%d]: nobody needs me... =(\n", getpid());
			break;
		}
		rc = read(child_in, &dns_params, sizeof(dns_params_t));
		if (rc < 0) {
			fprintf(stderr, "dns[%d]: Error: Could not read dns_params: "
					"%s\n", getpid(), strerror(errno));
			break;
		}
		if (rc == 0) {
			if (show_debug)
				printf("dns[%d]: Oops, father has gone, wait for me, wait...!\n", getpid());
			_exit(0);
		}
		if (dns_params.hostname[0] == '\0') {
			fprintf(stderr, "dns[%d]: Error: Parent requested resolution "
					"of an empty hostname (port = %d)!!!\n", getpid(),
					dns_params.port);
			_exit(1);
		}

#ifdef USE_IDN
		if (!dns_str_is_ascii(dns_params.hostname)) {
			rc = purple_network_convert_idn_to_ascii(dns_params.hostname, &hostname);
			if (rc != 0) {
				write_to_parent(child_out, &rc, sizeof(rc));
				if (show_debug)
					fprintf(stderr, "dns[%d] Error: IDN conversion returned "
							"%d\n", getpid(), rc);
				dns_params.hostname[0] = '\0';
				break;
			}
		} else /* intentional to execute the g_strdup */
#endif
		hostname = g_strdup(dns_params.hostname);

		/* We have the hostname and port, now resolve the IP */

#ifdef HAVE_GETADDRINFO
		g_snprintf(servname, sizeof(servname), "%d", dns_params.port);
		memset(&hints, 0, sizeof(hints));

		/* This is only used to convert a service
		 * name to a port number. As we know we are
		 * passing a number already, we know this
		 * value will not be really used by the C
		 * library.
		 */
		hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
		hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
		rc = getaddrinfo(hostname, servname, &hints, &res);
		write_to_parent(child_out, &rc, sizeof(rc));
		if (rc != 0) {
			if (show_debug)
				printf("dns[%d] Error: getaddrinfo returned %d\n",
					getpid(), rc);
			dns_params.hostname[0] = '\0';
			g_free(hostname);
			hostname = NULL;
			break;
		}
		tmp = res;
		while (res) {
			size_t ai_addrlen = res->ai_addrlen;
			write_to_parent(child_out, &ai_addrlen, sizeof(ai_addrlen));
			write_to_parent(child_out, res->ai_addr, res->ai_addrlen);
			res = res->ai_next;
		}
		freeaddrinfo(tmp);
#else
		struct hostent *hp;
		if (!(hp = gethostbyname(hostname))) {
			write_to_parent(child_out, &h_errno, sizeof(int));
			close(child_out);
			if (show_debug)
				printf("DNS Error: %d\n", h_errno);
			_exit(0);
		}
		memset(&sin, 0, sizeof(struct sockaddr_in));
		memcpy(&sin.sin_addr.s_addr, hp->h_addr, hp->h_length);
		sin.sin_family = hp->h_addrtype;

		sin.sin_port = htons(dns_params.port);
		rc = 0;
		write_to_parent(child_out, &rc, sizeof(rc));
		write_to_parent(child_out, &addrlen, sizeof(addrlen));
		write_to_parent(child_out, &sin, addrlen);
#endif
		write_to_parent(child_out, &zero, sizeof(zero));
		dns_params.hostname[0] = '\0';

		g_free(hostname);
		hostname = NULL;
	}

	close(child_out);
	close(child_in);

	_exit(0);
}
/*
 * End the DNS resolver child process functions.
 */

/*
 * Begin the functions for dealing with the DNS child processes.
 */
static void
cope_with_gdb_brokenness(void)
{
#ifdef __linux__
	static gboolean already_done = FALSE;
	char s[256], e[512];
	int n;
	pid_t ppid;

	if(already_done)
		return;
	already_done = TRUE;
	ppid = getppid();
	g_snprintf(s, sizeof(s), "/proc/%d/exe", ppid);
	n = readlink(s, e, sizeof(e));
	if(n < 0)
		return;

	e[MIN(n,sizeof(e)-1)] = '\0';

	if(strstr(e,"gdb")) {
		purple_debug_info("dns",
				   "Debugger detected, performing useless query...\n");
		gethostbyname("x.x.x.x.x");
	}
#endif
}

static void
purple_dnsquery_resolver_destroy(PurpleDnsQueryResolverProcess *resolver)
{
	g_return_if_fail(resolver != NULL);

	/* Keep this before the kill() call below. */
	if (resolver->inpa != 0) {
		purple_input_remove(resolver->inpa);
		resolver->inpa = 0;
	}

	/*
	 * We might as well attempt to kill our child process.  It really
	 * doesn't matter if this fails, because children will expire on
	 * their own after a few seconds.
	 */
	if (resolver->dns_pid > 0)
		kill(resolver->dns_pid, SIGKILL);

	close(resolver->fd_in);
	close(resolver->fd_out);

	g_free(resolver);

	number_of_dns_children--;
}

static PurpleDnsQueryResolverProcess *
purple_dnsquery_resolver_new(gboolean show_debug)
{
	PurpleDnsQueryResolverProcess *resolver;
	int child_out[2], child_in[2];

	/* Create pipes for communicating with the child process */
	if (pipe(child_out) || pipe(child_in)) {
		purple_debug_error("dns",
				   "Could not create pipes: %s\n", g_strerror(errno));
		return NULL;
	}

	resolver = g_new(PurpleDnsQueryResolverProcess, 1);
	resolver->inpa = 0;

	cope_with_gdb_brokenness();

	/* "Go fork and multiply." --Tommy Caldwell (Emily's dad, not the climber) */
	resolver->dns_pid = fork();

	/* If we are the child process... */
	if (resolver->dns_pid == 0) {
		/* We should not access the parent's side of the pipes, so close them */
		close(child_out[0]);
		close(child_in[1]);

		purple_dnsquery_resolver_run(child_out[1], child_in[0], show_debug);
		/* The thread calls _exit() rather than returning, so we never get here */
	}

	/* We should not access the child's side of the pipes, so close them */
	close(child_out[1]);
	close(child_in[0]);
	if (resolver->dns_pid == -1) {
		purple_debug_error("dns",
				   "Could not create child process for DNS: %s\n",
				   g_strerror(errno));
		purple_dnsquery_resolver_destroy(resolver);
		return NULL;
	}

	resolver->fd_out = child_out[0];
	resolver->fd_in = child_in[1];
	number_of_dns_children++;
	purple_debug_info("dns",
			   "Created new DNS child %d, there are now %d children.\n",
			   resolver->dns_pid, number_of_dns_children);

	return resolver;
}

/**
 * @return TRUE if the request was sent succesfully.  FALSE
 *         if the request could not be sent.  This isn't
 *         necessarily an error.  If the child has expired,
 *         for example, we won't be able to send the message.
 */
static gboolean
send_dns_request_to_child(PurpleDnsQueryData *query_data,
		PurpleDnsQueryResolverProcess *resolver)
{
	pid_t pid;
	dns_params_t dns_params;
	ssize_t rc;

	/* This waitpid might return the child's PID if it has recently
	 * exited, or it might return an error if it exited "long
	 * enough" ago that it has already been reaped; in either
	 * instance, we can't use it. */
	pid = waitpid(resolver->dns_pid, NULL, WNOHANG);
	if (pid > 0) {
		purple_debug_warning("dns", "DNS child %d no longer exists\n",
				resolver->dns_pid);
		purple_dnsquery_resolver_destroy(resolver);
		return FALSE;
	} else if (pid < 0) {
		purple_debug_warning("dns", "Wait for DNS child %d failed: %s\n",
				resolver->dns_pid, g_strerror(errno));
		purple_dnsquery_resolver_destroy(resolver);
		return FALSE;
	}

	/* Copy the hostname and port into a single data structure */
	strncpy(dns_params.hostname, query_data->hostname, sizeof(dns_params.hostname) - 1);
	dns_params.hostname[sizeof(dns_params.hostname) - 1] = '\0';
	dns_params.port = query_data->port;

	/* Send the data structure to the child */
	rc = write(resolver->fd_in, &dns_params, sizeof(dns_params));
	if (rc < 0) {
		purple_debug_error("dns", "Unable to write to DNS child %d: %s\n",
				resolver->dns_pid, g_strerror(errno));
		purple_dnsquery_resolver_destroy(resolver);
		return FALSE;
	}
	if (rc < sizeof(dns_params)) {
		purple_debug_error("dns", "Tried to write %" G_GSSIZE_FORMAT
				" bytes to child but only wrote %" G_GSSIZE_FORMAT "\n",
				sizeof(dns_params), rc);
		purple_dnsquery_resolver_destroy(resolver);
		return FALSE;
	}

	purple_debug_info("dns",
			"Successfully sent DNS request to child %d\n",
			resolver->dns_pid);

	query_data->resolver = resolver;

	return TRUE;
}

static void host_resolved(gpointer data, gint source, PurpleInputCondition cond);

static void
handle_next_queued_request(void)
{
	PurpleDnsQueryData *query_data;
	PurpleDnsQueryResolverProcess *resolver;

	if (queued_requests == NULL)
		/* No more DNS queries, yay! */
		return;

	query_data = queued_requests->data;
	queued_requests = g_slist_delete_link(queued_requests, queued_requests);

	/*
	 * If we have any children, attempt to have them perform the DNS
	 * query.  If we're able to send the query then resolver will be
	 * set to the PurpleDnsQueryResolverProcess.  Otherwise, resolver
	 * will be NULL and we'll need to create a new DNS request child.
	 */
	while (free_dns_children != NULL)
	{
		resolver = free_dns_children->data;
		free_dns_children = g_slist_remove(free_dns_children, resolver);

		if (send_dns_request_to_child(query_data, resolver))
			/* We found an acceptable child, yay */
			break;
	}

	/* We need to create a new DNS request child */
	if (query_data->resolver == NULL)
	{
		if (number_of_dns_children >= MAX_DNS_CHILDREN)
		{
			/* Apparently all our children are busy */
			queued_requests = g_slist_prepend(queued_requests, query_data);
			return;
		}

		resolver = purple_dnsquery_resolver_new(purple_debug_is_enabled());
		if (resolver == NULL)
		{
			purple_dnsquery_failed(query_data, _("Unable to create new resolver process\n"));
			return;
		}
		if (!send_dns_request_to_child(query_data, resolver))
		{
			purple_dnsquery_failed(query_data, _("Unable to send request to resolver process\n"));
			return;
		}
	}

	query_data->resolver->inpa = purple_input_add(query_data->resolver->fd_out,
			PURPLE_INPUT_READ, host_resolved, query_data);
}

/*
 * End the functions for dealing with the DNS child processes.
 */

static void
host_resolved(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleDnsQueryData *query_data;
	int rc, err;
	GSList *hosts = NULL;
	struct sockaddr *addr = NULL;
	size_t addrlen;
	char message[1024];

	query_data = data;

	purple_debug_info("dns", "Got response for '%s'\n", query_data->hostname);
	purple_input_remove(query_data->resolver->inpa);
	query_data->resolver->inpa = 0;

	rc = read(query_data->resolver->fd_out, &err, sizeof(err));
	if ((rc == 4) && (err != 0))
	{
#ifdef HAVE_GETADDRINFO
		g_snprintf(message, sizeof(message), _("Error resolving %s:\n%s"),
				query_data->hostname, purple_gai_strerror(err));
#else
		g_snprintf(message, sizeof(message), _("Error resolving %s: %d"),
				query_data->hostname, err);
#endif
		/* Re-read resolv.conf and friends in case DNS servers have changed */
		res_init();

		purple_dnsquery_failed(query_data, message);
	} else if (rc > 0) {
		/* Success! */
		while (rc > 0) {
			rc = read(query_data->resolver->fd_out, &addrlen, sizeof(addrlen));
			if (rc > 0 && addrlen > 0) {
				addr = g_malloc(addrlen);
				rc = read(query_data->resolver->fd_out, addr, addrlen);
				hosts = g_slist_append(hosts, GINT_TO_POINTER(addrlen));
				hosts = g_slist_append(hosts, addr);
			} else {
				break;
			}
		}
		/*	wait4(resolver->dns_pid, NULL, WNOHANG, NULL); */
		purple_dnsquery_resolved(query_data, hosts);

	} else if (rc == -1) {
		g_snprintf(message, sizeof(message), _("Error reading from resolver process:\n%s"), g_strerror(errno));
		purple_dnsquery_failed(query_data, message);

	} else if (rc == 0) {
		g_snprintf(message, sizeof(message), _("Resolver process exited without answering our request"));
		purple_dnsquery_failed(query_data, message);
	}

	handle_next_queued_request();
}

static void
resolve_host(PurpleDnsQueryData *query_data)
{
	queued_requests = g_slist_append(queued_requests, query_data);

	handle_next_queued_request();
}

#elif defined _WIN32 /* end PURPLE_DNSQUERY_USE_FORK  */

/*
 * Windows!
 */

static gboolean
dns_main_thread_cb(gpointer data)
{
	PurpleDnsQueryData *query_data = data;

	/* We're done, so purple_dnsquery_destroy() shouldn't think it is canceling an in-progress lookup */
	query_data->resolver = NULL;

	if (query_data->error_message != NULL)
		purple_dnsquery_failed(query_data, query_data->error_message);
	else
	{
		GSList *hosts;

		/* We don't want purple_dns_query_resolved() to free(hosts) */
		hosts = query_data->hosts;
		query_data->hosts = NULL;
		purple_dnsquery_resolved(query_data, hosts);
	}

	return FALSE;
}

static gpointer
dns_thread(gpointer data)
{
	PurpleDnsQueryData *query_data;
#ifdef HAVE_GETADDRINFO
	int rc;
	struct addrinfo hints, *res, *tmp;
	char servname[20];
#else
	struct sockaddr_in sin;
	struct hostent *hp;
#endif
	char *hostname;

	query_data = data;

#ifdef USE_IDN
	if (!dns_str_is_ascii(query_data->hostname)) {
		rc = purple_network_convert_idn_to_ascii(query_data->hostname, &hostname);
		if (rc != 0) {
			query_data->error_message = g_strdup_printf(_("Error converting %s "
					"to punycode: %d"), query_data->hostname, rc);
			/* back to main thread */
			purple_timeout_add(0, dns_main_thread_cb, query_data);
			return 0;
		}
	} else /* intentional fallthru */
#endif
	hostname = g_strdup(query_data->hostname);

#ifdef HAVE_GETADDRINFO
	g_snprintf(servname, sizeof(servname), "%d", query_data->port);
	memset(&hints,0,sizeof(hints));

	/*
	 * This is only used to convert a service
	 * name to a port number. As we know we are
	 * passing a number already, we know this
	 * value will not be really used by the C
	 * library.
	 */
	hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
	if ((rc = getaddrinfo(hostname, servname, &hints, &res)) == 0) {
		tmp = res;
		while(res) {
			query_data->hosts = g_slist_append(query_data->hosts,
				GSIZE_TO_POINTER(res->ai_addrlen));
			query_data->hosts = g_slist_append(query_data->hosts,
				g_memdup(res->ai_addr, res->ai_addrlen));
			res = res->ai_next;
		}
		freeaddrinfo(tmp);
	} else {
		query_data->error_message = g_strdup_printf(_("Error resolving %s:\n%s"), query_data->hostname, purple_gai_strerror(rc));
	}
#else
	if ((hp = gethostbyname(hostname))) {
		memset(&sin, 0, sizeof(struct sockaddr_in));
		memcpy(&sin.sin_addr.s_addr, hp->h_addr, hp->h_length);
		sin.sin_family = hp->h_addrtype;
		sin.sin_port = htons(query_data->port);

		query_data->hosts = g_slist_append(query_data->hosts,
				GSIZE_TO_POINTER(sizeof(sin)));
		query_data->hosts = g_slist_append(query_data->hosts,
				g_memdup(&sin, sizeof(sin)));
	} else {
		query_data->error_message = g_strdup_printf(_("Error resolving %s: %d"), query_data->hostname, h_errno);
	}
#endif
	g_free(hostname);

	/* back to main thread */
	purple_timeout_add(0, dns_main_thread_cb, query_data);

	return 0;
}

static void
resolve_host(PurpleDnsQueryData *query_data)
{
	GError *err = NULL;

	/*
	 * Spin off a separate thread to perform the DNS lookup so
	 * that we don't block the UI.
	 */
	query_data->resolver = g_thread_create(dns_thread,
			query_data, FALSE, &err);
	if (query_data->resolver == NULL)
	{
		char message[1024];
		g_snprintf(message, sizeof(message), _("Thread creation failure: %s"),
				(err && err->message) ? err->message : _("Unknown reason"));
		g_error_free(err);
		purple_dnsquery_failed(query_data, message);
	}
}

#else /* not PURPLE_DNSQUERY_USE_FORK or _WIN32 */

/*
 * We weren't able to do anything fancier above, so use the
 * fail-safe name resolution code, which is blocking.
 */

static void
resolve_host(PurpleDnsQueryData *query_data)
{
	struct sockaddr_in sin;
	GSList *hosts = NULL;
	struct hostent *hp;
	gchar *hostname;
#ifdef USE_IDN
	if (!dns_str_is_ascii(query_data->hostname)) {
		int ret = purple_network_convert_idn_to_ascii(query_data->hostname,
				&hostname);
		if (ret != 0) {
			char message[1024];
			g_snprintf(message, sizeof(message), _("Error resolving %s: %d"),
					query_data->hostname, ret);
			purple_dnsquery_failed(query_data, message);
			return;
		}
	} else /* fallthrough is intentional to the g_strdup */
#endif
	hostname = g_strdup(query_data->hostname);

	if(!(hp = gethostbyname(hostname))) {
		char message[1024];
		g_snprintf(message, sizeof(message), _("Error resolving %s: %d"),
				query_data->hostname, h_errno);
		purple_dnsquery_failed(query_data, message);
		g_free(hostname);
		return;
	}
	memset(&sin, 0, sizeof(struct sockaddr_in));
	memcpy(&sin.sin_addr.s_addr, hp->h_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
	g_free(hostname);
	sin.sin_port = htons(query_data->port);

	hosts = g_slist_append(hosts, GINT_TO_POINTER(sizeof(sin)));
	hosts = g_slist_append(hosts, g_memdup(&sin, sizeof(sin)));

	purple_dnsquery_resolved(query_data, hosts);
}

#endif /* not PURPLE_DNSQUERY_USE_FORK or _WIN32 */

static gboolean
initiate_resolving(gpointer data)
{
	PurpleDnsQueryData *query_data;
	PurpleProxyType proxy_type;

	query_data = data;
	query_data->timeout = 0;

	if (resolve_ip(query_data))
		/* resolve_ip calls purple_dnsquery_resolved */
		return FALSE;

	proxy_type = purple_proxy_info_get_type(
		purple_proxy_get_setup(query_data->account));
	if (proxy_type == PURPLE_PROXY_TOR) {
		purple_dnsquery_failed(query_data,
			_("Aborting DNS lookup in Tor Proxy mode."));
		return FALSE;
	}

	if (purple_dnsquery_ui_resolve(query_data))
		/* The UI is handling the resolve; we're done */
		return FALSE;

	resolve_host(query_data);

	return FALSE;
}

PurpleDnsQueryData *
purple_dnsquery_a_account(PurpleAccount *account, const char *hostname, int port,
				PurpleDnsQueryConnectFunction callback, gpointer data)
{
	PurpleDnsQueryData *query_data;

	g_return_val_if_fail(hostname != NULL, NULL);
	g_return_val_if_fail(port != 0, NULL);
	g_return_val_if_fail(callback != NULL, NULL);

	purple_debug_info("dnsquery", "Performing DNS lookup for %s\n", hostname);

	query_data = g_new0(PurpleDnsQueryData, 1);
	query_data->hostname = g_strdup(hostname);
	g_strstrip(query_data->hostname);
	query_data->port = port;
	query_data->callback = callback;
	query_data->data = data;
	query_data->account = account;

	if (*query_data->hostname == '\0')
	{
		purple_dnsquery_destroy(query_data);
		g_return_val_if_reached(NULL);
	}

	query_data->timeout = purple_timeout_add(0, initiate_resolving, query_data);

	return query_data;
}

PurpleDnsQueryData *
purple_dnsquery_a(const char *hostname, int port,
				PurpleDnsQueryConnectFunction callback, gpointer data)
{
	return purple_dnsquery_a_account(NULL, hostname, port, callback, data);
}

void
purple_dnsquery_destroy(PurpleDnsQueryData *query_data)
{
	PurpleDnsQueryUiOps *ops = purple_dnsquery_get_ui_ops();

	if (ops && ops->destroy)
		ops->destroy(query_data);

#if defined(PURPLE_DNSQUERY_USE_FORK)
	queued_requests = g_slist_remove(queued_requests, query_data);

	if (query_data->resolver != NULL)
		/*
		 * This is only non-NULL when we're cancelling an in-progress
		 * query.  Ideally we would tell our resolver child to stop
		 * resolving shit and then we would add it back to the
		 * free_dns_children linked list.  However, it's hard to tell
		 * children stuff, they just don't listen.  So we'll just
		 * kill the process and allow a new child to be started if we
		 * have more stuff to resolve.
		 */
		purple_dnsquery_resolver_destroy(query_data->resolver);
#elif defined _WIN32 /* end PURPLE_DNSQUERY_USE_FORK */
	if (query_data->resolver != NULL)
	{
		/*
		 * It's not really possible to kill a thread.  So instead we
		 * just set the callback to NULL and let the DNS lookup
		 * finish.
		 */
		query_data->callback = NULL;
		return;
	}

	while (query_data->hosts != NULL)
	{
		/* Discard the length... */
		query_data->hosts = g_slist_remove(query_data->hosts, query_data->hosts->data);
		/* Free the address... */
		g_free(query_data->hosts->data);
		query_data->hosts = g_slist_remove(query_data->hosts, query_data->hosts->data);
	}
	g_free(query_data->error_message);
#endif /* end _WIN32 */

	if (query_data->timeout > 0)
		purple_timeout_remove(query_data->timeout);

	g_free(query_data->hostname);
	g_free(query_data);
}

char *
purple_dnsquery_get_host(PurpleDnsQueryData *query_data)
{
	g_return_val_if_fail(query_data != NULL, NULL);

	return query_data->hostname;
}

unsigned short
purple_dnsquery_get_port(PurpleDnsQueryData *query_data)
{
	g_return_val_if_fail(query_data != NULL, 0);

	return query_data->port;
}

void
purple_dnsquery_set_ui_ops(PurpleDnsQueryUiOps *ops)
{
	dns_query_ui_ops = ops;
}

PurpleDnsQueryUiOps *
purple_dnsquery_get_ui_ops(void)
{
	/* It is perfectly acceptable for dns_query_ui_ops to be NULL; this just
	 * means that the default platform-specific implementation will be used.
	 */
	return dns_query_ui_ops;
}

void
purple_dnsquery_init(void)
{
}

void
purple_dnsquery_uninit(void)
{
#if defined(PURPLE_DNSQUERY_USE_FORK)
	while (free_dns_children != NULL)
	{
		purple_dnsquery_resolver_destroy(free_dns_children->data);
		free_dns_children = g_slist_remove(free_dns_children, free_dns_children->data);
	}
#endif /* end PURPLE_DNSQUERY_USE_FORK */
}
