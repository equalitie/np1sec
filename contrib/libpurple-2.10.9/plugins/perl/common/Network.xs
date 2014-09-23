#include "module.h"

MODULE = Purple::Network  PACKAGE = Purple::Network  PREFIX = purple_network_
PROTOTYPES: ENABLE

const char *
purple_network_get_local_system_ip(fd)
	int fd

const char *
purple_network_get_my_ip(fd)
	int fd

unsigned short
purple_network_get_port_from_fd(fd)
	int fd

const char *
purple_network_get_public_ip()

const unsigned char *
purple_network_ip_atoi(ip)
	const char *ip
PPCODE:
	RETVAL = purple_network_ip_atoi(ip);
	sv_setpvn(TARG, (const char *)RETVAL, 4);
	XSprePUSH;
	PUSHTARG;

Purple::NetworkListenData
purple_network_listen(port, socket_type, cb, cb_data)
	unsigned short port
	int socket_type
	Purple::NetworkListenCallback cb
	gpointer cb_data

Purple::NetworkListenData
purple_network_listen_range(start, end, socket_type, cb, cb_data)
	unsigned short start
	unsigned short end
	int socket_type
	Purple::NetworkListenCallback cb
	gpointer cb_data

void
purple_network_set_public_ip(ip)
	const char *ip
