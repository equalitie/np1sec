/**
 * @file ssl-gnutls.c GNUTLS SSL plugin.
 *
 * purple
 *
 * Copyright (C) 2003 Christian Hammond <chipx86@gnupdate.org>
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
#include "internal.h"
#include "debug.h"
#include "certificate.h"
#include "plugin.h"
#include "sslconn.h"
#include "version.h"
#include "util.h"

#define SSL_GNUTLS_PLUGIN_ID "ssl-gnutls"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

typedef struct
{
	gnutls_session session;
	guint handshake_handler;
	guint handshake_timer;
} PurpleSslGnutlsData;

#define PURPLE_SSL_GNUTLS_DATA(gsc) ((PurpleSslGnutlsData *)gsc->private_data)

static gnutls_certificate_client_credentials xcred = NULL;

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
/* Priority strings.  The default one is, well, the default (and is always
 * set).  The hash table is of the form hostname => priority (both
 * char *).
 *
 * We only use a gnutls_priority_t for the default on the assumption that
 * that's the more common case.  Improvement patches (like matching on
 * subdomains) welcome.
 */
static gnutls_priority_t default_priority = NULL;
static GHashTable *host_priorities = NULL;
#endif

static void
ssl_gnutls_log(int level, const char *str)
{
	/* GnuTLS log messages include the '\n' */
	purple_debug_misc("gnutls", "lvl %d: %s", level, str);
}

static void
ssl_gnutls_init_gnutls(void)
{
	const char *debug_level;
	const char *host_priorities_str;

	/* Configure GnuTLS to use glib memory management */
	/* I expect that this isn't really necessary, but it may prevent
	   some bugs */
	/* TODO: It may be necessary to wrap this allocators for GnuTLS.
	   If there are strange bugs, perhaps look here (yes, I am a
	   hypocrite) */
	gnutls_global_set_mem_functions(
		(gnutls_alloc_function)   g_malloc, /* malloc */
		(gnutls_alloc_function)   g_malloc, /* secure malloc */
		NULL,      /* mem_is_secure */
		(gnutls_realloc_function) g_realloc, /* realloc */
		(gnutls_free_function)    g_free     /* free */
		);

	debug_level = g_getenv("PURPLE_GNUTLS_DEBUG");
	if (debug_level) {
		int level = atoi(debug_level);
		if (level < 0) {
			purple_debug_warning("gnutls", "Assuming log level 0 instead of %d\n",
			                     level);
			level = 0;
		}

		/* "The level is an integer between 0 and 9. Higher values mean more verbosity." */
		gnutls_global_set_log_level(level);
		gnutls_global_set_log_function(ssl_gnutls_log);
	}

	/* Expected format: host=priority;host2=priority;*=priority
	 * where "*" is used to override the default priority string for
	 * libpurple.
	 */
	host_priorities_str = g_getenv("PURPLE_GNUTLS_PRIORITIES");
	if (host_priorities_str) {
#ifndef HAVE_GNUTLS_PRIORITY_FUNCS
		purple_debug_warning("gnutls", "Warning, PURPLE_GNUTLS_PRIORITIES "
		                     "environment variable set, but we were built "
		                     "against an older GnuTLS that doesn't support "
		                     "this. :-(");
#else /* HAVE_GNUTLS_PRIORITY_FUNCS */
		char **entries = g_strsplit(host_priorities_str, ";", -1);
		char *default_priority_str = NULL;
		guint i;

		host_priorities = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                        g_free, g_free);

		for (i = 0; entries[i]; ++i) {
			char *host = entries[i];
			char *equals = strchr(host, '=');
			char *prio_str;

			if (equals) {
				*equals = '\0';
				prio_str = equals + 1;

				/* Empty? */
				if (*prio_str == '\0') {
					purple_debug_warning("gnutls", "Ignoring empty priority "
					                               "string for %s\n", host);
				} else {
					/* TODO: Validate each of these and complain */
					if (g_str_equal(host, "*")) {
						/* Override the default priority */
						g_free(default_priority_str);
						default_priority_str = g_strdup(prio_str);
					} else
						g_hash_table_insert(host_priorities, g_strdup(host),
						                    g_strdup(prio_str));
				}
			}
		}

		if (default_priority_str) {
			if (gnutls_priority_init(&default_priority, default_priority_str, NULL)) {
				purple_debug_warning("gnutls", "Unable to set default priority to %s\n",
				                     default_priority_str);
				/* Versions of GnuTLS as of 2.8.6 (2010-03-31) don't free/NULL
				 * this on error.
				 */
				gnutls_free(default_priority);
				default_priority = NULL;
			}

			g_free(default_priority_str);
		}

		g_strfreev(entries);
#endif /* HAVE_GNUTLS_PRIORITY_FUNCS */
	}

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	/* Make sure we set have a default priority! */
	if (!default_priority) {
		if (gnutls_priority_init(&default_priority, "NORMAL:%SSL3_RECORD_VERSION", NULL)) {
			/* See comment above about memory leak */
			gnutls_free(default_priority);
			gnutls_priority_init(&default_priority, "NORMAL", NULL);
		}
	}
#endif /* HAVE_GNUTLS_PRIORITY_FUNCS */

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&xcred);

	/* TODO: I can likely remove this */
	gnutls_certificate_set_x509_trust_file(xcred, "ca.pem",
		GNUTLS_X509_FMT_PEM);
}

static gboolean
ssl_gnutls_init(void)
{
	return TRUE;
}

static void
ssl_gnutls_uninit(void)
{
	gnutls_global_deinit();

	gnutls_certificate_free_credentials(xcred);
	xcred = NULL;

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	if (host_priorities) {
		g_hash_table_destroy(host_priorities);
		host_priorities = NULL;
	}

	gnutls_priority_deinit(default_priority);
	default_priority = NULL;
#endif
}

static void
ssl_gnutls_verified_cb(PurpleCertificateVerificationStatus st,
		       gpointer userdata)
{
	PurpleSslConnection *gsc = (PurpleSslConnection *) userdata;

	if (st == PURPLE_CERTIFICATE_VALID) {
		/* Certificate valid? Good! Do the connection! */
		gsc->connect_cb(gsc->connect_cb_data, gsc, PURPLE_INPUT_READ);
	} else {
		/* Otherwise, signal an error */
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CERTIFICATE_INVALID,
				      gsc->connect_cb_data);
		purple_ssl_close(gsc);
	}
}



static void ssl_gnutls_handshake_cb(gpointer data, gint source,
		PurpleInputCondition cond)
{
	PurpleSslConnection *gsc = data;
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t ret;

	/*purple_debug_info("gnutls", "Handshaking with %s\n", gsc->host);*/
	ret = gnutls_handshake(gnutls_data->session);

	if(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return;

	purple_input_remove(gnutls_data->handshake_handler);
	gnutls_data->handshake_handler = 0;

	if(ret != 0) {
		purple_debug_error("gnutls", "Handshake failed. Error %s\n",
			gnutls_strerror(ret));

		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
	} else {
		/* Now we are cooking with gas! */
		PurpleSslOps *ops = purple_ssl_get_ops();
		GList * peers = ops->get_peer_certificates(gsc);

		PurpleCertificateScheme *x509 =
			purple_certificate_find_scheme("x509");

		GList * l;

		/* TODO: Remove all this debugging babble */
		purple_debug_info("gnutls", "Handshake complete\n");

		for (l=peers; l; l = l->next) {
			PurpleCertificate *crt = l->data;
			GByteArray *z =
				x509->get_fingerprint_sha1(crt);
			gchar * fpr =
				purple_base16_encode_chunked(z->data,
							     z->len);

			purple_debug_info("gnutls/x509",
					  "Key print: %s\n",
					  fpr);

			/* Kill the cert! */
			x509->destroy_certificate(crt);

			g_free(fpr);
			g_byte_array_free(z, TRUE);
		}
		g_list_free(peers);

		{
			const gnutls_datum *cert_list;
			unsigned int cert_list_size = 0;
			gnutls_session session=gnutls_data->session;
			int i;

			cert_list =
				gnutls_certificate_get_peers(session, &cert_list_size);

			purple_debug_info("gnutls",
					    "Peer provided %d certs\n",
					    cert_list_size);
			for (i=0; i<cert_list_size; i++)
			{
				gchar fpr_bin[256];
				gsize fpr_bin_sz = sizeof(fpr_bin);
				gchar * fpr_asc = NULL;
				gchar tbuf[256];
				gsize tsz=sizeof(tbuf);
				gchar * tasc = NULL;
				gnutls_x509_crt cert;

				gnutls_x509_crt_init(&cert);
				gnutls_x509_crt_import (cert, &cert_list[i],
						GNUTLS_X509_FMT_DER);

				gnutls_x509_crt_get_fingerprint(cert, GNUTLS_MAC_SHA,
						fpr_bin, &fpr_bin_sz);

				fpr_asc =
						purple_base16_encode_chunked((const guchar *)fpr_bin, fpr_bin_sz);

				purple_debug_info("gnutls",
						"Lvl %d SHA1 fingerprint: %s\n",
						i, fpr_asc);

				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_serial(cert,tbuf,&tsz);
				tasc=purple_base16_encode_chunked((const guchar *)tbuf, tsz);
				purple_debug_info("gnutls",
						"Serial: %s\n",
						tasc);
				g_free(tasc);

				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_dn (cert, tbuf, &tsz);
				purple_debug_info("gnutls",
						"Cert DN: %s\n",
						tbuf);
				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_issuer_dn (cert, tbuf, &tsz);
				purple_debug_info("gnutls",
						"Cert Issuer DN: %s\n",
						tbuf);

				g_free(fpr_asc);
				fpr_asc = NULL;
				gnutls_x509_crt_deinit(cert);
			}
		}

		/* TODO: The following logic should really be in libpurple */
		/* If a Verifier was given, hand control over to it */
		if (gsc->verifier) {
			GList *peers;
			/* First, get the peer cert chain */
			peers = purple_ssl_get_peer_certificates(gsc);

			/* Now kick off the verification process */
			purple_certificate_verify(gsc->verifier,
						  gsc->host,
						  peers,
						  ssl_gnutls_verified_cb,
						  gsc);

			purple_certificate_destroy_list(peers);
		} else {
			/* Otherwise, just call the "connection complete"
			   callback */
			gsc->connect_cb(gsc->connect_cb_data, gsc, cond);
		}
	}

}

static gboolean
start_handshake_cb(gpointer data)
{
	PurpleSslConnection *gsc = data;
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);

	purple_debug_info("gnutls", "Starting handshake with %s\n", gsc->host);

	gnutls_data->handshake_timer = 0;

	ssl_gnutls_handshake_cb(gsc, gsc->fd, PURPLE_INPUT_READ);
	return FALSE;
}

static void
ssl_gnutls_connect(PurpleSslConnection *gsc)
{
	PurpleSslGnutlsData *gnutls_data;
	static const int cert_type_priority[2] = { GNUTLS_CRT_X509, 0 };

	gnutls_data = g_new0(PurpleSslGnutlsData, 1);
	gsc->private_data = gnutls_data;

	gnutls_init(&gnutls_data->session, GNUTLS_CLIENT);
#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	{
		const char *prio_str = NULL;
		gboolean set = FALSE;

		/* Let's see if someone has specified a specific priority */
		if (gsc->host && host_priorities)
			prio_str = g_hash_table_lookup(host_priorities, gsc->host);

		if (prio_str)
			set = (GNUTLS_E_SUCCESS ==
					gnutls_priority_set_direct(gnutls_data->session, prio_str,
				                               NULL));

		if (!set)
			gnutls_priority_set(gnutls_data->session, default_priority);
	}
#else
	gnutls_set_default_priority(gnutls_data->session);
#endif

	gnutls_certificate_type_set_priority(gnutls_data->session,
		cert_type_priority);

	gnutls_credentials_set(gnutls_data->session, GNUTLS_CRD_CERTIFICATE,
		xcred);

	gnutls_transport_set_ptr(gnutls_data->session, GINT_TO_POINTER(gsc->fd));

	gnutls_data->handshake_handler = purple_input_add(gsc->fd,
		PURPLE_INPUT_READ, ssl_gnutls_handshake_cb, gsc);

	/* Orborde asks: Why are we configuring a callback, then
	   (almost) immediately calling it?

	   Answer: gnutls_handshake (up in handshake_cb) needs to be called
	   once in order to get the ball rolling on the SSL connection.
	   Once it has done so, only then will the server reply, triggering
	   the callback.

	   Since the logic driving gnutls_handshake is the same with the first
	   and subsequent calls, we'll just fire the callback immediately to
	   accomplish this.
	*/
	gnutls_data->handshake_timer = purple_timeout_add(0, start_handshake_cb,
	                                                  gsc);
}

static void
ssl_gnutls_close(PurpleSslConnection *gsc)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);

	if(!gnutls_data)
		return;

	if(gnutls_data->handshake_handler)
		purple_input_remove(gnutls_data->handshake_handler);
	if (gnutls_data->handshake_timer)
		purple_timeout_remove(gnutls_data->handshake_timer);

	gnutls_bye(gnutls_data->session, GNUTLS_SHUT_RDWR);

	gnutls_deinit(gnutls_data->session);

	g_free(gnutls_data);
	gsc->private_data = NULL;
}

static size_t
ssl_gnutls_read(PurpleSslConnection *gsc, void *data, size_t len)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t s;

	s = gnutls_record_recv(gnutls_data->session, data, len);

	if(s == GNUTLS_E_AGAIN || s == GNUTLS_E_INTERRUPTED) {
		s = -1;
		errno = EAGAIN;
	} else if(s < 0) {
		purple_debug_error("gnutls", "receive failed: %s\n",
				gnutls_strerror(s));
		s = -1;
		/*
		 * TODO: Set errno to something more appropriate.  Or even
		 *       better: allow ssl plugins to keep track of their
		 *       own error message, then add a new ssl_ops function
		 *       that returns the error message.
		 */
		errno = EIO;
	}

	return s;
}

static size_t
ssl_gnutls_write(PurpleSslConnection *gsc, const void *data, size_t len)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t s = 0;

	/* XXX: when will gnutls_data be NULL? */
	if(gnutls_data)
		s = gnutls_record_send(gnutls_data->session, data, len);

	if(s == GNUTLS_E_AGAIN || s == GNUTLS_E_INTERRUPTED) {
		s = -1;
		errno = EAGAIN;
	} else if(s < 0) {
		purple_debug_error("gnutls", "send failed: %s\n",
				gnutls_strerror(s));
		s = -1;
		/*
		 * TODO: Set errno to something more appropriate.  Or even
		 *       better: allow ssl plugins to keep track of their
		 *       own error message, then add a new ssl_ops function
		 *       that returns the error message.
		 */
		errno = EIO;
	}

	return s;
}

/* Forward declarations are fun! */
static PurpleCertificate *
x509_import_from_datum(const gnutls_datum dt, gnutls_x509_crt_fmt mode);
/* indeed! */
static gboolean
x509_certificate_signed_by(PurpleCertificate * crt,
			   PurpleCertificate * issuer);
static void
x509_destroy_certificate(PurpleCertificate * crt);

static GList *
ssl_gnutls_get_peer_certificates(PurpleSslConnection * gsc)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	PurpleCertificate *prvcrt = NULL;

	/* List of Certificate instances to return */
	GList * peer_certs = NULL;

	/* List of raw certificates as given by GnuTLS */
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;

	unsigned int i;

	/* This should never, ever happen. */
	g_return_val_if_fail( gnutls_certificate_type_get (gnutls_data->session) == GNUTLS_CRT_X509, NULL);

	/* Get the certificate list from GnuTLS */
	/* TODO: I am _pretty sure_ this doesn't block or do other exciting things */
	cert_list = gnutls_certificate_get_peers(gnutls_data->session,
						 &cert_list_size);

	/* Convert each certificate to a Certificate and append it to the list */
	for (i = 0; i < cert_list_size; i++) {
		PurpleCertificate * newcrt = x509_import_from_datum(cert_list[i],
							      GNUTLS_X509_FMT_DER);
		/* Append is somewhat inefficient on linked lists, but is easy
		   to read. If someone complains, I'll change it.
		   TODO: Is anyone complaining? (Maybe elb?) */
		/* only append if previous cert was actually signed by this one.
		 * Thanks Microsoft. */
		if ((prvcrt == NULL) || x509_certificate_signed_by(prvcrt, newcrt)) {
			peer_certs = g_list_append(peer_certs, newcrt);
			prvcrt = newcrt;
		} else {
			x509_destroy_certificate(newcrt);
			purple_debug_error("gnutls", "Dropping further peer certificates "
			                             "because the chain is broken!\n");
			break;
		}
	}

	/* cert_list doesn't need free()-ing */

	return peer_certs;
}

/************************************************************************/
/* X.509 functionality                                                  */
/************************************************************************/
const gchar * SCHEME_NAME = "x509";

static PurpleCertificateScheme x509_gnutls;

/** Refcounted GnuTLS certificate data instance */
typedef struct {
	gint refcount;
	gnutls_x509_crt crt;
} x509_crtdata_t;

/** Helper functions for reference counting */
static x509_crtdata_t *
x509_crtdata_addref(x509_crtdata_t *cd)
{
	(cd->refcount)++;
	return cd;
}

static void
x509_crtdata_delref(x509_crtdata_t *cd)
{
	(cd->refcount)--;

	if (cd->refcount < 0)
		g_critical("Refcount of x509_crtdata_t is %d, which is less "
				"than zero!\n", cd->refcount);

	/* If the refcount reaches zero, kill the structure */
	if (cd->refcount <= 0) {
		/* Kill the internal data */
		gnutls_x509_crt_deinit( cd->crt );
		/* And kill the struct */
		g_free( cd );
	}
}

/** Helper macro to retrieve the GnuTLS crt_t from a PurpleCertificate */
#define X509_GET_GNUTLS_DATA(pcrt) ( ((x509_crtdata_t *) (pcrt->data))->crt)

/** Transforms a gnutls_datum containing an X.509 certificate into a Certificate instance under the x509_gnutls scheme
 *
 * @param dt   Datum to transform
 * @param mode GnuTLS certificate format specifier (GNUTLS_X509_FMT_PEM for
 *             reading from files, and GNUTLS_X509_FMT_DER for converting
 *             "over the wire" certs for SSL)
 *
 * @return A newly allocated Certificate structure of the x509_gnutls scheme
 */
static PurpleCertificate *
x509_import_from_datum(const gnutls_datum dt, gnutls_x509_crt_fmt mode)
{
	/* Internal certificate data structure */
	x509_crtdata_t *certdat;
	/* New certificate to return */
	PurpleCertificate * crt;

	/* Allocate and prepare the internal certificate data */
	certdat = g_new0(x509_crtdata_t, 1);
	gnutls_x509_crt_init(&(certdat->crt));
	certdat->refcount = 0;

	/* Perform the actual certificate parse */
	/* Yes, certdat->crt should be passed as-is */
	gnutls_x509_crt_import(certdat->crt, &dt, mode);

	/* Allocate the certificate and load it with data */
	crt = g_new0(PurpleCertificate, 1);
	crt->scheme = &x509_gnutls;
	crt->data = x509_crtdata_addref(certdat);

	return crt;
}

/** Imports a PEM-formatted X.509 certificate from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A newly allocated Certificate structure of the x509_gnutls scheme
 */
static PurpleCertificate *
x509_import_from_file(const gchar * filename)
{
	PurpleCertificate *crt;  /* Certificate being constructed */
	gchar *buf;        /* Used to load the raw file data */
	gsize buf_sz;      /* Size of the above */
	gnutls_datum dt; /* Struct to pass down to GnuTLS */

	purple_debug_info("gnutls",
			  "Attempting to load X.509 certificate from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	g_return_val_if_fail(
		g_file_get_contents(filename,
			    &buf,
			    &buf_sz,
			    NULL      /* No error checking for now */
		),
		NULL);

	/* Load the datum struct */
	dt.data = (unsigned char *) buf;
	dt.size = buf_sz;

	/* Perform the conversion; files should be in PEM format */
	crt = x509_import_from_datum(dt, GNUTLS_X509_FMT_PEM);

	/* Cleanup */
	g_free(buf);

	return crt;
}

/** Imports a number of PEM-formatted X.509 certificates from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A newly allocated GSList of Certificate structures of the x509_gnutls scheme
 */
static GSList *
x509_importcerts_from_file(const gchar * filename)
{
	PurpleCertificate *crt;  /* Certificate being constructed */
	gchar *buf;        /* Used to load the raw file data */
	gchar *begin, *end;
	GSList *crts = NULL;
	gsize buf_sz;      /* Size of the above */
	gnutls_datum dt; /* Struct to pass down to GnuTLS */

	purple_debug_info("gnutls",
			  "Attempting to load X.509 certificates from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	g_return_val_if_fail(
		g_file_get_contents(filename,
			    &buf,
			    &buf_sz,
			    NULL      /* No error checking for now */
		),
		NULL);

	begin = buf;
	while((end = strstr(begin, "-----END CERTIFICATE-----")) != NULL) {
		end += sizeof("-----END CERTIFICATE-----")-1;
		/* Load the datum struct */
		dt.data = (unsigned char *) begin;
		dt.size = (end-begin);

		/* Perform the conversion; files should be in PEM format */
		crt = x509_import_from_datum(dt, GNUTLS_X509_FMT_PEM);
		crts = g_slist_prepend(crts, crt);
		begin = end;
	}

	/* Cleanup */
	g_free(buf);

	return crts;
}

/**
 * Exports a PEM-formatted X.509 certificate to the specified file.
 * @param filename Filename to export to. Format will be PEM
 * @param crt      Certificate to export
 *
 * @return TRUE if success, otherwise FALSE
 */
static gboolean
x509_export_certificate(const gchar *filename, PurpleCertificate *crt)
{
	gnutls_x509_crt crt_dat; /* GnuTLS cert struct */
	int ret;
	gchar * out_buf; /* Data to output */
	size_t out_size; /* Output size */
	gboolean success = FALSE;

	/* Paranoia paranoia paranoia! */
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(crt->data, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	/* Obtain the output size required */
	out_size = 0;
	ret = gnutls_x509_crt_export(crt_dat, GNUTLS_X509_FMT_PEM,
				     NULL, /* Provide no buffer yet */
				     &out_size /* Put size here */
		);
	g_return_val_if_fail(ret == GNUTLS_E_SHORT_MEMORY_BUFFER, FALSE);

	/* Now allocate a buffer and *really* export it */
	out_buf = g_new0(gchar, out_size);
	ret = gnutls_x509_crt_export(crt_dat, GNUTLS_X509_FMT_PEM,
				     out_buf, /* Export to our new buffer */
				     &out_size /* Put size here */
		);
	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Failed to export cert to buffer with code %d\n",
				   ret);
		g_free(out_buf);
		return FALSE;
	}

	/* Write it out to an actual file */
	success = purple_util_write_data_to_file_absolute(filename,
							  out_buf, out_size);

	g_free(out_buf);
	return success;
}

static PurpleCertificate *
x509_copy_certificate(PurpleCertificate *crt)
{
	x509_crtdata_t *crtdat;
	PurpleCertificate *newcrt;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	crtdat = (x509_crtdata_t *) crt->data;

	newcrt = g_new0(PurpleCertificate, 1);
	newcrt->scheme = &x509_gnutls;
	newcrt->data = x509_crtdata_addref(crtdat);

	return newcrt;
}
/** Frees a Certificate
 *
 * Destroys a Certificate's internal data structures and frees the pointer
 * given.
 * @param crt Certificate instance to be destroyed. It WILL NOT be destroyed
 *            if it is not of the correct CertificateScheme. Can be NULL
 *
 */
static void
x509_destroy_certificate(PurpleCertificate * crt)
{
	if (NULL == crt) return;

	/* Check that the scheme is x509_gnutls */
	if ( crt->scheme != &x509_gnutls ) {
		purple_debug_error("gnutls",
				   "destroy_certificate attempted on certificate of wrong scheme (scheme was %s, expected %s)\n",
				   crt->scheme->name,
				   SCHEME_NAME);
		return;
	}

	g_return_if_fail(crt->data != NULL);
	g_return_if_fail(crt->scheme != NULL);

	/* Use the reference counting system to free (or not) the
	   underlying data */
	x509_crtdata_delref((x509_crtdata_t *)crt->data);

	/* Kill the structure itself */
	g_free(crt);
}

/** Determines whether one certificate has been issued and signed by another
 *
 * @param crt       Certificate to check the signature of
 * @param issuer    Issuer's certificate
 *
 * @return TRUE if crt was signed and issued by issuer, otherwise FALSE
 * @TODO  Modify this function to return a reason for invalidity?
 */
static gboolean
x509_certificate_signed_by(PurpleCertificate * crt,
			   PurpleCertificate * issuer)
{
	gnutls_x509_crt crt_dat;
	gnutls_x509_crt issuer_dat;
	unsigned int verify; /* used to store result from GnuTLS verifier */
	int ret;
	gchar *crt_id = NULL;
	gchar *issuer_id = NULL;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(issuer, FALSE);

	/* Verify that both certs are the correct scheme */
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(issuer->scheme == &x509_gnutls, FALSE);

	/* TODO: check for more nullness? */

	crt_dat = X509_GET_GNUTLS_DATA(crt);
	issuer_dat = X509_GET_GNUTLS_DATA(issuer);

	/* First, let's check that crt.issuer is actually issuer */
	ret = gnutls_x509_crt_check_issuer(crt_dat, issuer_dat);
	if (ret <= 0) {

		if (ret < 0) {
			purple_debug_error("gnutls/x509",
					   "GnuTLS error %d while checking certificate issuer match.",
					   ret);
		} else {
			gchar *crt_id, *issuer_id, *crt_issuer_id;
			crt_id = purple_certificate_get_unique_id(crt);
			issuer_id = purple_certificate_get_unique_id(issuer);
			crt_issuer_id =
				purple_certificate_get_issuer_unique_id(crt);
			purple_debug_info("gnutls/x509",
					  "Certificate %s is issued by "
					  "%s, which does not match %s.\n",
					  crt_id ? crt_id : "(null)",
					  crt_issuer_id ? crt_issuer_id : "(null)",
					  issuer_id ? issuer_id : "(null)");
			g_free(crt_id);
			g_free(issuer_id);
			g_free(crt_issuer_id);
		}

		/* The issuer is not correct, or there were errors */
		return FALSE;
	}

	/* Now, check the signature */
	/* The second argument is a ptr to an array of "trusted" issuer certs,
	   but we're only using one trusted one */
	ret = gnutls_x509_crt_verify(crt_dat, &issuer_dat, 1,
				     /* Permit signings by X.509v1 certs
					(Verisign and possibly others have
					root certificates that predate the
					current standard) */
				     GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
				     &verify);

	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Attempted certificate verification caused a GnuTLS error code %d. I will just say the signature is bad, but you should look into this.\n", ret);
		return FALSE;
	}

#ifdef HAVE_GNUTLS_CERT_INSECURE_ALGORITHM
	if (verify & GNUTLS_CERT_INSECURE_ALGORITHM) {
		/*
		 * A certificate in the chain is signed with an insecure
		 * algorithm. Put a warning into the log to make this error
		 * perfectly clear as soon as someone looks at the debug log is
		 * generated.
		 */
		crt_id = purple_certificate_get_unique_id(crt);
		issuer_id = purple_certificate_get_issuer_unique_id(crt);
		purple_debug_warning("gnutls/x509",
				"Insecure hash algorithm used by %s to sign %s\n",
				issuer_id, crt_id);
	}
#endif

	if (verify & GNUTLS_CERT_INVALID) {
		/* Signature didn't check out, but at least
		   there were no errors*/
		if (!crt_id)
			crt_id = purple_certificate_get_unique_id(crt);
		if (!issuer_id)
			issuer_id = purple_certificate_get_issuer_unique_id(crt);
		purple_debug_error("gnutls/x509",
				  "Bad signature from %s on %s\n",
				  issuer_id, crt_id);
		g_free(crt_id);
		g_free(issuer_id);

		return FALSE;
	} /* if (ret, etc.) */

	/* If we got here, the signature is good */
	return TRUE;
}

static GByteArray *
x509_sha1sum(PurpleCertificate *crt)
{
	size_t hashlen = 20; /* SHA1 hashes are 20 bytes */
	size_t tmpsz = hashlen; /* Throw-away variable for GnuTLS to stomp on*/
	gnutls_x509_crt crt_dat;
	GByteArray *hash; /**< Final hash container */
	guchar hashbuf[hashlen]; /**< Temporary buffer to contain hash */

	g_return_val_if_fail(crt, NULL);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	/* Extract the fingerprint */
	g_return_val_if_fail(
		0 == gnutls_x509_crt_get_fingerprint(crt_dat, GNUTLS_MAC_SHA,
						     hashbuf, &tmpsz),
		NULL);

	/* This shouldn't happen */
	g_return_val_if_fail(tmpsz == hashlen, NULL);

	/* Okay, now create and fill hash array */
	hash = g_byte_array_new();
	g_byte_array_append(hash, hashbuf, hashlen);

	return hash;
}

static gchar *
x509_cert_dn (PurpleCertificate *crt)
{
	gnutls_x509_crt cert_dat;
	gchar *dn = NULL;
	size_t dn_size;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Distinguished Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	dn_size = 0;
	gnutls_x509_crt_get_dn(cert_dat, dn, &dn_size);

	/* Now allocate and get the Distinguished Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	dn = g_new0(gchar, ++dn_size);
	if (0 != gnutls_x509_crt_get_dn(cert_dat, dn, &dn_size)) {
		purple_debug_error("gnutls/x509",
				   "Failed to get Distinguished Name\n");
		g_free(dn);
		return NULL;
	}

	return dn;
}

static gchar *
x509_issuer_dn (PurpleCertificate *crt)
{
	gnutls_x509_crt cert_dat;
	gchar *dn = NULL;
	size_t dn_size;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Distinguished Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	dn_size = 0;
	gnutls_x509_crt_get_issuer_dn(cert_dat, dn, &dn_size);

	/* Now allocate and get the Distinguished Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	dn = g_new0(gchar, ++dn_size);
	if (0 != gnutls_x509_crt_get_issuer_dn(cert_dat, dn, &dn_size)) {
		purple_debug_error("gnutls/x509",
				   "Failed to get issuer's Distinguished "
				   "Name\n");
		g_free(dn);
		return NULL;
	}

	return dn;
}

static gchar *
x509_common_name (PurpleCertificate *crt)
{
	gnutls_x509_crt cert_dat;
	gchar *cn = NULL;
	size_t cn_size;
	int ret;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Common Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	cn_size = 0;
	gnutls_x509_crt_get_dn_by_oid(cert_dat,
				      GNUTLS_OID_X520_COMMON_NAME,
				      0, /* First CN found, please */
				      0, /* Not in raw mode */
				      cn, &cn_size);

	/* Now allocate and get the Common Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	cn = g_new0(gchar, ++cn_size);
	ret = gnutls_x509_crt_get_dn_by_oid(cert_dat,
					    GNUTLS_OID_X520_COMMON_NAME,
					    0, /* First CN found, please */
					    0, /* Not in raw mode */
					    cn, &cn_size);
	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Failed to get Common Name\n");
		g_free(cn);
		return NULL;
	}

	return cn;
}

static gboolean
x509_check_name (PurpleCertificate *crt, const gchar *name)
{
	gnutls_x509_crt crt_dat;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(name, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	if (gnutls_x509_crt_check_hostname(crt_dat, name)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean
x509_times (PurpleCertificate *crt, time_t *activation, time_t *expiration)
{
	gnutls_x509_crt crt_dat;
	/* GnuTLS time functions return this on error */
	const time_t errval = (time_t) (-1);
	gboolean success = TRUE;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	if (activation) {
		*activation = gnutls_x509_crt_get_activation_time(crt_dat);
		if (*activation == errval)
			success = FALSE;
	}
	if (expiration) {
		*expiration = gnutls_x509_crt_get_expiration_time(crt_dat);
		if (*expiration == errval)
			success = FALSE;
	}

	return success;
}

/* X.509 certificate operations provided by this plugin */
static PurpleCertificateScheme x509_gnutls = {
	"x509",                          /* Scheme name */
	N_("X.509 Certificates"),        /* User-visible scheme name */
	x509_import_from_file,           /* Certificate import function */
	x509_export_certificate,         /* Certificate export function */
	x509_copy_certificate,           /* Copy */
	x509_destroy_certificate,        /* Destroy cert */
	x509_certificate_signed_by,      /* Signature checker */
	x509_sha1sum,                    /* SHA1 fingerprint */
	x509_cert_dn,                    /* Unique ID */
	x509_issuer_dn,                  /* Issuer Unique ID */
	x509_common_name,                /* Subject name */
	x509_check_name,                 /* Check subject name */
	x509_times,                      /* Activation/Expiration time */
	x509_importcerts_from_file,      /* Multiple certificates import function */

	NULL,
	NULL,
	NULL

};

static PurpleSslOps ssl_ops =
{
	ssl_gnutls_init,
	ssl_gnutls_uninit,
	ssl_gnutls_connect,
	ssl_gnutls_close,
	ssl_gnutls_read,
	ssl_gnutls_write,
	ssl_gnutls_get_peer_certificates,

	/* padding */
	NULL,
	NULL,
	NULL
};

static gboolean
plugin_load(PurplePlugin *plugin)
{
	if(!purple_ssl_get_ops()) {
		purple_ssl_set_ops(&ssl_ops);
	}

	/* Init GNUTLS now so others can use it even if sslconn never does */
	ssl_gnutls_init_gnutls();

	/* Register that we're providing an X.509 CertScheme */
	purple_certificate_register_scheme( &x509_gnutls );

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	if(purple_ssl_get_ops() == &ssl_ops) {
		purple_ssl_set_ops(NULL);
	}

	purple_certificate_unregister_scheme( &x509_gnutls );

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	PURPLE_PLUGIN_FLAG_INVISIBLE,                       /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	SSL_GNUTLS_PLUGIN_ID,                             /**< id             */
	N_("GNUTLS"),                                     /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Provides SSL support through GNUTLS."),
	                                                  /**  description    */
	N_("Provides SSL support through GNUTLS."),
	"Christian Hammond <chipx86@gnupdate.org>",
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	NULL,                                             /**< actions        */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(ssl_gnutls, init_plugin, info)
