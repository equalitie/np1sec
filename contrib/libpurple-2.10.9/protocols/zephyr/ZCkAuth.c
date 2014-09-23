/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZCheckAuthentication function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

/* Check authentication of the notice.
   If it looks authentic but fails the Kerberos check, return -1.
   If it looks authentic and passes the Kerberos check, return 1.
   If it doesn't look authentic, return 0

   When not using Kerberos, return true if the notice claims to be authentic.
   Only used by clients; the server uses its own routine.
 */
Code_t ZCheckAuthentication(notice, from)
    ZNotice_t *notice;
    struct sockaddr_in *from;
{
#ifdef ZEPHYR_USES_KERBEROS
    int result;
    ZChecksum_t our_checksum;
    CREDENTIALS cred;

    /* If the value is already known, return it. */
    if (notice->z_checked_auth != ZAUTH_UNSET)
	return (notice->z_checked_auth);

    if (!notice->z_auth)
	return (ZAUTH_NO);

    if ((result = krb_get_cred(SERVER_SERVICE, SERVER_INSTANCE,
			       __Zephyr_realm, &cred)) != 0)
	return (ZAUTH_NO);

#ifdef NOENCRYPTION
    our_checksum = 0;
#else
    our_checksum = des_quad_cksum(notice->z_packet, NULL,
				  notice->z_default_format+
				  strlen(notice->z_default_format)+1-
				  notice->z_packet, 0, (C_Block *)cred.session);
#endif
    /* if mismatched checksum, then the packet was corrupted */
    return ((our_checksum == notice->z_checksum) ? ZAUTH_YES : ZAUTH_FAILED);

#else
    return (notice->z_auth ? ZAUTH_YES : ZAUTH_NO);
#endif
}
