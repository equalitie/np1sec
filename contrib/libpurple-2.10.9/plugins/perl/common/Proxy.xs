#include "module.h"

MODULE = Purple::Proxy  PACKAGE = Purple::Proxy  PREFIX = purple_proxy_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::ProxyType", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_PROXY_##name}
		const_iv(USE_GLOBAL),
		const_iv(NONE),
		const_iv(HTTP),
		const_iv(SOCKS4),
		const_iv(SOCKS5),
		const_iv(USE_ENVVAR),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::Handle
purple_proxy_get_handle()

MODULE = Purple::Proxy  PACKAGE = Purple::ProxyInfo  PREFIX = purple_proxy_info_
PROTOTYPES: ENABLE

void
purple_proxy_info_destroy(info)
	Purple::ProxyInfo info

const char *
purple_proxy_info_get_host(info)
	Purple::ProxyInfo info

const char *
purple_proxy_info_get_password(info)
	Purple::ProxyInfo info

int
purple_proxy_info_get_port(info)
	Purple::ProxyInfo info

Purple::ProxyType
purple_proxy_info_get_type(info)
	Purple::ProxyInfo info

const char *
purple_proxy_info_get_username(info)
	Purple::ProxyInfo info

Purple::ProxyInfo
purple_proxy_info_new()

void
purple_proxy_info_set_host(info, host)
	Purple::ProxyInfo info
	const char *host

void
purple_proxy_info_set_password(info, password)
	Purple::ProxyInfo info
	const char *password

void
purple_proxy_info_set_port(info, port)
	Purple::ProxyInfo info
	int port

void
purple_proxy_info_set_type(info, type)
	Purple::ProxyInfo info
	Purple::ProxyType type

void
purple_proxy_info_set_username(info, username)
	Purple::ProxyInfo info
	const char *username

MODULE = Purple::Proxy  PACKAGE = Purple::Proxy  PREFIX = purple_
PROTOTYPES: ENABLE

Purple::ProxyInfo
purple_global_proxy_get_info()
