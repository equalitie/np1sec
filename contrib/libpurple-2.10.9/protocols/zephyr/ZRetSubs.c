/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZRetrieveSubscriptions and
 * ZRetrieveDefaultSubscriptions functions.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1988,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

static Code_t Z_RetSubs(ZNotice_t *notice, int *nsubs, Z_AuthProc auth_routine);

/* Need STDC definition when possible for unsigned short argument. */
#ifdef __STDC__
Code_t ZRetrieveSubscriptions(unsigned short port, int *nsubs)
#else
Code_t ZRetrieveSubscriptions(port,nsubs)
	unsigned short port;
	int *nsubs;
#endif
{
	int retval;
	ZNotice_t notice;
	char asciiport[50];

	if (!port)			/* use default port */
	    port = __Zephyr_port;

	retval = ZMakeAscii16(asciiport, sizeof(asciiport), ntohs(port));
	if (retval != ZERR_NONE)
		return (retval);

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_message = asciiport;
	notice.z_message_len = strlen(asciiport)+1;
	notice.z_opcode = CLIENT_GIMMESUBS;

	return(Z_RetSubs(&notice, nsubs, ZAUTH));
}

#if 0
Code_t ZRetrieveDefaultSubscriptions(nsubs)
	int *nsubs;
{
	ZNotice_t notice;

	(void) memset((char *)&notice, 0, sizeof(notice));
	notice.z_message = (char *) 0;
	notice.z_message_len = 0;
	notice.z_opcode = CLIENT_GIMMEDEFS;

	return(Z_RetSubs(&notice, nsubs, ZNOAUTH));

}
#endif

static Code_t Z_RetSubs(notice, nsubs, auth_routine)
	register ZNotice_t *notice;
	int *nsubs;
	Z_AuthProc auth_routine;
{
	register int i;
	int retval,nrecv,gimmeack;
	ZNotice_t retnotice;
	char *ptr,*end,*ptr2;

	retval = ZFlushSubscriptions();

	if (retval != ZERR_NONE && retval != ZERR_NOSUBSCRIPTIONS)
		return (retval);

	if (ZGetFD() < 0)
		if ((retval = ZOpenPort((unsigned short *)0)) != ZERR_NONE)
			return (retval);

	notice->z_kind = ACKED;
	notice->z_port = __Zephyr_port;
	notice->z_class = ZEPHYR_CTL_CLASS;
	notice->z_class_inst = ZEPHYR_CTL_CLIENT;
	notice->z_sender = 0;
	notice->z_recipient = "";
	notice->z_default_format = "";

	if ((retval = ZSendNotice(notice,auth_routine)) != ZERR_NONE)
		return (retval);

	nrecv = 0;
	gimmeack = 0;
	__subscriptions_list = (ZSubscription_t *) 0;

	while (!nrecv || !gimmeack) {
		retval = Z_WaitForNotice (&retnotice, ZCompareMultiUIDPred,
					  &notice->z_multiuid, SRV_TIMEOUT);
		if (retval == ZERR_NONOTICE)
		  return ETIMEDOUT;
		else if (retval != ZERR_NONE)
		  return retval;

		if (retnotice.z_kind == SERVNAK) {
			ZFreeNotice(&retnotice);
			return (ZERR_SERVNAK);
		}
		/* non-matching protocol version numbers means the
		   server is probably an older version--must punt */
		if (strcmp(notice->z_version,retnotice.z_version)) {
			ZFreeNotice(&retnotice);
			return(ZERR_VERS);
		}
		if (retnotice.z_kind == SERVACK &&
		    !strcmp(retnotice.z_opcode,notice->z_opcode)) {
			ZFreeNotice(&retnotice);
			gimmeack = 1;
			continue;
		}

		if (retnotice.z_kind != ACKED) {
			ZFreeNotice(&retnotice);
			return (ZERR_INTERNAL);
		}

		nrecv++;

		end = retnotice.z_message+retnotice.z_message_len;

		__subscriptions_num = 0;
		for (ptr=retnotice.z_message;ptr<end;ptr++)
			if (!*ptr)
				__subscriptions_num++;

		__subscriptions_num = __subscriptions_num / 3;

		__subscriptions_list = (ZSubscription_t *)
			malloc((unsigned)(__subscriptions_num*
					  sizeof(ZSubscription_t)));
		if (__subscriptions_num && !__subscriptions_list) {
			ZFreeNotice(&retnotice);
			return (ENOMEM);
		}

		for (ptr=retnotice.z_message,i = 0; i< __subscriptions_num; i++) {
			size_t len;

			len = strlen(ptr) + 1;
			__subscriptions_list[i].zsub_class = (char *)
				malloc(len);
			if (!__subscriptions_list[i].zsub_class) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			g_strlcpy(__subscriptions_list[i].zsub_class,ptr,len);
			ptr += len;
			len = strlen(ptr) + 1;
			__subscriptions_list[i].zsub_classinst = (char *)
				malloc(len);
			if (!__subscriptions_list[i].zsub_classinst) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			g_strlcpy(__subscriptions_list[i].zsub_classinst,ptr,len);
			ptr += len;
			ptr2 = ptr;
			if (!*ptr2)
				ptr2 = "*";
			len = strlen(ptr2) + 1;
			__subscriptions_list[i].zsub_recipient = (char *)
				malloc(len);
			if (!__subscriptions_list[i].zsub_recipient) {
				ZFreeNotice(&retnotice);
				return (ENOMEM);
			}
			g_strlcpy(__subscriptions_list[i].zsub_recipient,ptr2,len);
			ptr += strlen(ptr)+1;
		}
		ZFreeNotice(&retnotice);
	}

	__subscriptions_next = 0;
	*nsubs = __subscriptions_num;

	return (ZERR_NONE);
}
