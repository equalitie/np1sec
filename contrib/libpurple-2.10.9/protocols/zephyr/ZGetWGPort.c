/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetWGPort function.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "internal.h"

int ZGetWGPort()
{
    char *envptr, name[128];
    FILE *fp;
    int wgport;
#ifdef WIN32
    long int buffsize= 128;
    char tempdir[buffsize];
#endif
    envptr = getenv("WGFILE");
    if (!envptr) {
#ifdef WIN32
         GetTempPath(buffsize,tempdir);
         GetTempFileName(tempdir,"wg.",0,name);
#else
	(void) sprintf(name, "/tmp/wg.%d", getuid());
#endif
	envptr = name;
    }
    if (!(fp = fopen(envptr, "r")))
	return (-1);

    /* if fscanf fails, return -1 via wgport */
    if (fscanf(fp, "%d", &wgport) != 1)
	    wgport = -1;

    (void) fclose(fp);

    return (wgport);
}
