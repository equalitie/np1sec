/**
 * @file sslconn.c SSL API
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
 */
#define _PURPLE_SSLCONN_C_

#include "internal.h"

#include "certificate.h"
#include "debug.h"
#include "request.h"
#include "sslconn.h"

static gboolean _ssl_initialized = FALSE;
static PurpleSslOps *_ssl_ops = NULL;

static gboolean
ssl_init(void)
{
	PurplePlugin *plugin;
	PurpleSslOps *ops;

	if (_ssl_initialized)
		return FALSE;

	plugin = purple_plugins_find_with_id("core-ssl");

	if (plugin != NULL && !purple_plugin_is_loaded(plugin))
		purple_plugin_load(plugin);

	ops = purple_ssl_get_ops();
	if ((ops == NULL) || (ops->init == NULL) || (ops->uninit == NULL) ||
		(ops->connectfunc == NULL) || (ops->close == NULL) ||
		(ops->read == NULL) || (ops->write == NULL))
	{
		return FALSE;
	}

	return (_ssl_initialized = ops->init());
}

gboolean
purple_ssl_is_supported(void)
{
#ifdef HAVE_SSL
	ssl_init();
	return (purple_ssl_get_ops() != NULL);
#else
	return FALSE;
#endif
}

static void
purple_ssl_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleSslConnection *gsc;
	PurpleSslOps *ops;

	gsc = data;
	gsc->connect_data = NULL;

	if (source < 0)
	{
		if (gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CONNECT_FAILED, gsc->connect_cb_data);

		purple_ssl_close(gsc);
		return;
	}

	gsc->fd = source;

	ops = purple_ssl_get_ops();
	ops->connectfunc(gsc);
}

PurpleSslConnection *
purple_ssl_connect(PurpleAccount *account, const char *host, int port,
				 PurpleSslInputFunction func, PurpleSslErrorFunction error_func,
				 void *data)
{
	return purple_ssl_connect_with_ssl_cn(account, host, port, func, error_func,
	                                  NULL, data);
}

PurpleSslConnection *
purple_ssl_connect_with_ssl_cn(PurpleAccount *account, const char *host, int port,
				 PurpleSslInputFunction func, PurpleSslErrorFunction error_func,
				 const char *ssl_cn, void *data)
{
	PurpleSslConnection *gsc;

	g_return_val_if_fail(host != NULL,            NULL);
	g_return_val_if_fail(port != 0 && port != -1, NULL);
	g_return_val_if_fail(func != NULL,            NULL);
	g_return_val_if_fail(purple_ssl_is_supported(), NULL);

	if (!_ssl_initialized)
	{
		if (!ssl_init())
			return NULL;
	}

	gsc = g_new0(PurpleSslConnection, 1);

	gsc->fd              = -1;
	gsc->host            = ssl_cn ? g_strdup(ssl_cn) : g_strdup(host);
	gsc->port            = port;
	gsc->connect_cb_data = data;
	gsc->connect_cb      = func;
	gsc->error_cb        = error_func;

	/* TODO: Move this elsewhere */
	gsc->verifier = purple_certificate_find_verifier("x509","tls_cached");

	gsc->connect_data = purple_proxy_connect(NULL, account, host, port, purple_ssl_connect_cb, gsc);

	if (gsc->connect_data == NULL)
	{
		g_free(gsc->host);
		g_free(gsc);

		return NULL;
	}

	return (PurpleSslConnection *)gsc;
}

static void
recv_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleSslConnection *gsc = data;

	gsc->recv_cb(gsc->recv_cb_data, gsc, cond);
}

void
purple_ssl_input_add(PurpleSslConnection *gsc, PurpleSslInputFunction func,
				   void *data)
{
	g_return_if_fail(func != NULL);
	g_return_if_fail(purple_ssl_is_supported());

	gsc->recv_cb_data = data;
	gsc->recv_cb      = func;

	gsc->inpa = purple_input_add(gsc->fd, PURPLE_INPUT_READ, recv_cb, gsc);
}

const gchar *
purple_ssl_strerror(PurpleSslErrorType error)
{
	switch(error) {
		case PURPLE_SSL_CONNECT_FAILED:
			return _("SSL Connection Failed");
		case PURPLE_SSL_HANDSHAKE_FAILED:
			return _("SSL Handshake Failed");
		case PURPLE_SSL_CERTIFICATE_INVALID:
			return _("SSL peer presented an invalid certificate");
		default:
			purple_debug_warning("sslconn", "Unknown SSL error code %d\n", error);
			return _("Unknown SSL error");
	}
}

PurpleSslConnection *
purple_ssl_connect_fd(PurpleAccount *account, int fd,
					PurpleSslInputFunction func,
					PurpleSslErrorFunction error_func,
                    void *data)
{
    return purple_ssl_connect_with_host_fd(account, fd, func, error_func, NULL, data);
}

PurpleSslConnection *
purple_ssl_connect_with_host_fd(PurpleAccount *account, int fd,
                      PurpleSslInputFunction func,
                      PurpleSslErrorFunction error_func,
                      const char *host,
                      void *data)
{
	PurpleSslConnection *gsc;
	PurpleSslOps *ops;

	g_return_val_if_fail(fd != -1,                NULL);
	g_return_val_if_fail(func != NULL,            NULL);
	g_return_val_if_fail(purple_ssl_is_supported(), NULL);

	if (!_ssl_initialized)
	{
		if (!ssl_init())
			return NULL;
	}

	gsc = g_new0(PurpleSslConnection, 1);

	gsc->connect_cb_data = data;
	gsc->connect_cb      = func;
	gsc->error_cb        = error_func;
	gsc->fd              = fd;
    if(host)
        gsc->host            = g_strdup(host);

	/* TODO: Move this elsewhere */
	gsc->verifier = purple_certificate_find_verifier("x509","tls_cached");


	ops = purple_ssl_get_ops();
	ops->connectfunc(gsc);

	return (PurpleSslConnection *)gsc;
}

void
purple_ssl_close(PurpleSslConnection *gsc)
{
	PurpleSslOps *ops;

	g_return_if_fail(gsc != NULL);

	purple_request_close_with_handle(gsc);
	purple_notify_close_with_handle(gsc);

	ops = purple_ssl_get_ops();
	(ops->close)(gsc);

	if (gsc->connect_data != NULL)
		purple_proxy_connect_cancel(gsc->connect_data);

	if (gsc->inpa > 0)
		purple_input_remove(gsc->inpa);

	if (gsc->fd >= 0)
		close(gsc->fd);

	g_free(gsc->host);
	g_free(gsc);
}

size_t
purple_ssl_read(PurpleSslConnection *gsc, void *data, size_t len)
{
	PurpleSslOps *ops;

	g_return_val_if_fail(gsc  != NULL, 0);
	g_return_val_if_fail(data != NULL, 0);
	g_return_val_if_fail(len  >  0,    0);

	ops = purple_ssl_get_ops();
	return (ops->read)(gsc, data, len);
}

size_t
purple_ssl_write(PurpleSslConnection *gsc, const void *data, size_t len)
{
	PurpleSslOps *ops;

	g_return_val_if_fail(gsc  != NULL, 0);
	g_return_val_if_fail(data != NULL, 0);
	g_return_val_if_fail(len  >  0,    0);

	ops = purple_ssl_get_ops();
	return (ops->write)(gsc, data, len);
}

GList *
purple_ssl_get_peer_certificates(PurpleSslConnection *gsc)
{
	PurpleSslOps *ops;

	g_return_val_if_fail(gsc != NULL, NULL);

	ops = purple_ssl_get_ops();
	return (ops->get_peer_certificates)(gsc);
}

void
purple_ssl_set_ops(PurpleSslOps *ops)
{
	_ssl_ops = ops;
}

PurpleSslOps *
purple_ssl_get_ops(void)
{
	return _ssl_ops;
}

void
purple_ssl_init(void)
{
	/* Although purple_ssl_is_supported will do the initialization on
	   command, SSL plugins tend to register CertificateSchemes as well
	   as providing SSL ops. */
	if (!ssl_init()) {
		purple_debug_error("sslconn", "Unable to initialize SSL.\n");
	}
}

void
purple_ssl_uninit(void)
{
	PurpleSslOps *ops;

	if (!_ssl_initialized)
		return;

	ops = purple_ssl_get_ops();
	ops->uninit();

	_ssl_initialized = FALSE;
}
