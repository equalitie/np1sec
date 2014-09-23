#include "module.h"

/* TODO


Purple::Ssl::Connection
purple_ssl_connect(account, host, port, func, error_func, data)
	Purple::Account account
	const char *host
	int port
	PurpleSslInputFunction func
	PurpleSslErrorFunction error_func

void
purple_ssl_input_add(gsc, func, data)
	Purple::Ssl::Connection gsc
	Purple::SslInputFunction func

Purple::Ssl::Connection
purple_ssl_connect_fd(account, fd, func, error_func, data)
	Purple::Account account
	int fd
	PurpleSslInputFunction func
	PurpleSslErrorFunction error_func

*/

MODULE = Purple::SSL  PACKAGE = Purple::SSL   PREFIX = purple_ssl_
PROTOTYPES: ENABLE

void
purple_ssl_close(gsc)
	Purple::Ssl::Connection gsc

Purple::Ssl::Ops
purple_ssl_get_ops()

gboolean
purple_ssl_is_supported()

size_t
purple_ssl_read(gsc, buffer, len)
	Purple::Ssl::Connection gsc
	void * buffer
	size_t len

void
purple_ssl_set_ops(ops)
	Purple::Ssl::Ops ops

size_t
purple_ssl_write(gsc, buffer, len)
	Purple::Ssl::Connection gsc
	void * buffer
	size_t len
