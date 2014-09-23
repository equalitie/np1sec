/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZParseNotice function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987,1991 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

/* Assume that strlen is efficient on this machine... */
#define next_field(ptr)	ptr += strlen (ptr) + 1

#if defined (__GNUC__) && defined (__vax__)
#undef next_field
static __inline__ char * Istrend (char *str) {
    /*
     * This should be faster on VAX models outside the 2 series.  Don't
     * use it if you are using MicroVAX 2 servers.  If you are using a
     * VS2 server, use something like
     *	#define next_field(ptr)		while(*ptr++)
     * instead of this code.
     *
     * This requires use of GCC to get the optimized code, but
     * everybody uses GCC, don't they? :-)
     */
    register char *str2 asm ("r1");
    /* Assumes that no field is longer than 64K.... */
    asm ("locc $0,$65535,(%1)" : "=r" (str2) : "r" (str) : "r0");
    return str2;
}
#define next_field(ptr) ptr = Istrend (ptr) + 1
#endif

#ifdef mips
#undef next_field
/*
 * The compiler doesn't optimize this macro as well as it does the
 * following function.
 */
#define next_fieldXXX(ptr) do{register unsigned c1,c2;c1= *ptr;	\
		   while((ptr++,c2= *ptr,c1)&&(ptr++,c1= *ptr,c2));}while(0)
static char *next_field_1 (s) char *s; {
    /*
     * Calling overhead is still present, but this routine is faster
     * than strlen, and doesn't bother with some of the other math
     * that we'd just have to undo later anyways.
     */
    register unsigned c1 = *s, c2;
    while (1) {
	s++; c2 = *s; if (c1 == 0) break;
	s++; c1 = *s; if (c2 == 0) break;
	s++; c2 = *s; if (c1 == 0) break;
	s++; c1 = *s; if (c2 == 0) break;
    }
    return s;
}
#define next_field(ptr)	ptr=next_field_1(ptr)
#endif

Code_t ZParseNotice(buffer, len, notice)
    char *buffer;
    int len;
    ZNotice_t *notice;
{
    char *ptr, *end;
    unsigned long temp;
    int maj, numfields, i;

#ifdef __LINE__
    int lineno;
    /* Note: This definition of BAD eliminates lint and compiler
     * complains about the "while (0)", but require that the macro not
     * be used as the "then" part of an "if" statement that also has
     * an "else" clause.
     */
#define BAD_PACKET	{lineno=__LINE__;goto badpkt;}
    /* This one gets lint/compiler complaints.  */
/*#define BAD	do{lineno=__LINE__;goto badpkt;}while(0)*/
#else
#define BAD_PACKET	goto badpkt
#endif

    (void) memset((char *)notice, 0, sizeof(ZNotice_t));

    ptr = buffer;
    end = buffer+len;

    notice->z_packet = buffer;

    notice->z_version = ptr;
    if (strncmp(ptr, ZVERSIONHDR, sizeof(ZVERSIONHDR) - 1))
	return (ZERR_VERS);
    ptr += sizeof(ZVERSIONHDR) - 1;
    if (!*ptr) {
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: null version string");
#endif
	return ZERR_BADPKT;
    }
    maj = atoi(ptr);
    if (maj != ZVERSIONMAJOR)
	return (ZERR_VERS);
    next_field (ptr);

    if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	BAD_PACKET;
    numfields = temp;
    next_field (ptr);

    /*XXX 3 */
    numfields -= 2; /* numfields, version, and checksum */
    if (numfields < 0) {
#ifdef __LINE__
	lineno = __LINE__;
      badpkt:
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: bad packet from %s/%d (line %d)",
		 inet_ntoa (notice->z_uid.zuid_addr.s_addr),
		 notice->z_port, lineno);
#endif
#else
    badpkt:
#ifdef Z_DEBUG
	Z_debug ("ZParseNotice: bad packet from %s/%d",
		 inet_ntoa (notice->z_uid.zuid_addr.s_addr),
		 notice->z_port);
#endif
#endif
	return ZERR_BADPKT;
    }

    if (numfields) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_kind = temp;
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;

    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)&notice->z_uid,
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_time.tv_sec = ntohl((unsigned long) notice->z_uid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl((unsigned long) notice->z_uid.tv.tv_usec);
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;

    if (numfields) {
	if (ZReadAscii16(ptr, end-ptr, &notice->z_port) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_port = htons(notice->z_port);
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;

    if (numfields) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_auth = temp;
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;
    notice->z_checked_auth = ZAUTH_UNSET;

    if (numfields) {
	if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_authent_len = temp;
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;

    if (numfields) {
	notice->z_ascii_authent = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	BAD_PACKET;

    if (numfields) {
	notice->z_class = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_class = "";

    if (numfields) {
	notice->z_class_inst = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_class_inst = "";

    if (numfields) {
	notice->z_opcode = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_opcode = "";

    if (numfields) {
	notice->z_sender = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_sender = "";

    if (numfields) {
	notice->z_recipient = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_recipient = "";

    if (numfields) {
	notice->z_default_format = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_default_format = "";

/*XXX*/
    if (ZReadAscii32(ptr, end-ptr, &temp) == ZERR_BADFIELD)
	BAD_PACKET;
    notice->z_checksum = temp;
    numfields--;
    next_field (ptr);

    if (numfields) {
	notice->z_multinotice = ptr;
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_multinotice = "";

    if (numfields) {
	if (ZReadAscii(ptr, end-ptr, (unsigned char *)&notice->z_multiuid,
		       sizeof(ZUnique_Id_t)) == ZERR_BADFIELD)
	    BAD_PACKET;
	notice->z_time.tv_sec = ntohl((unsigned long) notice->z_multiuid.tv.tv_sec);
	notice->z_time.tv_usec = ntohl((unsigned long) notice->z_multiuid.tv.tv_usec);
	numfields--;
	next_field (ptr);
    }
    else
	notice->z_multiuid = notice->z_uid;

    for (i=0;i<Z_MAXOTHERFIELDS && numfields;i++,numfields--) {
	notice->z_other_fields[i] = ptr;
	next_field (ptr);
    }
    notice->z_num_other_fields = i;

    for (i=0;i<numfields;i++)
	next_field (ptr);

    notice->z_message = (void *)ptr;
    notice->z_message_len = len-(ptr-buffer);

    return (ZERR_NONE);
}
