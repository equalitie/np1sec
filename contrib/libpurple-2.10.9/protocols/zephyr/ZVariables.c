/* This file is part of the Project Athena Zephyr Notification System.
 * It contains source for the ZGetVariable, ZSetVariable, and ZUnsetVariable
 * functions.
 *
 *	Created by:	Robert French
 *
 *	Copyright (c) 1987 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h".
 */

#include "libpurple/internal.h"
#include "internal.h"
#include "util.h"

#include <ctype.h>
#ifndef WIN32
#include <pwd.h>
#endif

static char *get_localvarfile __P((void));
static char *get_varval __P((char *fn, char *val));
static int varline __P((char *bfr, char *var));

char *ZGetVariable(var)
    char *var;
{
	char *varfile, *ret;

	if ((varfile = get_localvarfile()) == NULL)
		return ((char *)0);

	ret = get_varval(varfile, var);
	g_free(varfile);
	if (ret != ZERR_NONE)
		return ret;

#ifdef WIN32
	varfile = g_strdup("C:\\zephyr\\zephyr.var");
#else
	varfile = g_strdup_printf("%s/zephyr.vars", CONFDIR);
#endif
	ret = get_varval(varfile, var);
	g_free(varfile);

	return ret;
}

Code_t ZSetVariable(var, value)
    char *var;
    char *value;
{
    int written;
    FILE *fpin, *fpout;
    char *varfile, *varfilebackup, varbfr[512];

    written = 0;

    if ((varfile = get_localvarfile()) == NULL)
	return (ZERR_INTERNAL);

    varfilebackup = g_strconcat(varfile, ".backup", NULL);

    if (!(fpout = fopen(varfilebackup, "w"))) {
	g_free(varfile);
	g_free(varfilebackup);
	return (errno);
    }
    if ((fpin = fopen(varfile, "r")) != NULL) {
	while (fgets(varbfr, sizeof varbfr, fpin) != (char *) 0) {
	    if (varbfr[strlen(varbfr)-1] < ' ')
		varbfr[strlen(varbfr)-1] = '\0';
	    if (varline(varbfr, var)) {
		fprintf(fpout, "%s = %s\n", var, value);
		written = 1;
	    }
	    else
		fprintf(fpout, "%s\n", varbfr);
	}
	(void) fclose(fpin);		/* don't care about errs on input */
    }
    if (!written)
	fprintf(fpout, "%s = %s\n", var, value);
    if (fclose(fpout) == EOF) {
    	g_free(varfilebackup);
    	g_free(varfile);
	return(EIO);		/* can't rely on errno */
    }
    if (rename(varfilebackup, varfile)) {
	g_free(varfilebackup);
	g_free(varfile);
	return (errno);
    }
    g_free(varfilebackup);
    g_free(varfile);
    return (ZERR_NONE);
}

Code_t ZUnsetVariable(var)
    char *var;
{
    FILE *fpin, *fpout;
    char *varfile, *varfilebackup, varbfr[512];

    if ((varfile = get_localvarfile()) == NULL)
	return (ZERR_INTERNAL);

    varfilebackup = g_strconcat(varfile, ".backup", NULL);

    if (!(fpout = fopen(varfilebackup, "w"))) {
	g_free(varfile);
	g_free(varfilebackup);
	return (errno);
    }
    if ((fpin = fopen(varfile, "r")) != NULL) {
	while (fgets(varbfr, sizeof varbfr, fpin) != (char *) 0) {
	    if (varbfr[strlen(varbfr)-1] < ' ')
		varbfr[strlen(varbfr)-1] = '\0';
	    if (!varline(varbfr, var))
		fprintf(fpout, "%s\n", varbfr);
	}
	(void) fclose(fpin);		/* don't care about read close errs */
    }
    if (fclose(fpout) == EOF) {
	g_free(varfilebackup);
	g_free(varfile);
	return(EIO);		/* errno isn't reliable */
    }
    if (rename(varfilebackup, varfile)) {
	g_free(varfilebackup);
	g_free(varfile);
	return (errno);
    }
    g_free(varfilebackup);
    g_free(varfile);
    return (ZERR_NONE);
}

static char *get_localvarfile(void)
{
    const char *base;
#ifndef WIN32
    struct passwd *pwd;
    base = purple_home_dir();
#else
    base = getenv("HOME");
    if (!base)
        base = getenv("HOMEPATH");
    if (!base)
        base = "C:\\";
#endif
    if (!base) {
#ifndef WIN32
	if (!(pwd = getpwuid((int) getuid()))) {
	    fprintf(stderr, "Zephyr internal failure: Can't find your entry in /etc/passwd\n");
	    return NULL;
	}
	base = pwd->pw_dir;
#endif
    }

    return g_strconcat(base, "/.zephyr.vars", NULL);
}

static char *get_varval(fn, var)
    char *fn;
    char *var;
{
    FILE *fp;
    static char varbfr[512];
    int i;

    fp = fopen(fn, "r");
    if (!fp)
	return ((char *)0);

    while (fgets(varbfr, sizeof varbfr, fp) != (char *) 0) {
	if (varbfr[strlen(varbfr)-1] < ' ')
	    varbfr[strlen(varbfr)-1] = '\0';
	if (!(i = varline(varbfr, var)))
	    continue;
	(void) fclose(fp);		/* open read-only, don't care */
	return (varbfr+i);
    }
    (void) fclose(fp);			/* open read-only, don't care */
    return ((char *)0);
}

/* If the variable in the line bfr[] is the same as var, return index to
   the variable value, else return 0. */
static int varline(bfr, var)
    char *bfr;
    char *var;
{
    register char *cp;


    if (!bfr[0] || bfr[0] == '#')	/* comment or null line */
	return (0);

    cp = bfr;
    while (*cp && !isspace(*cp) && (*cp != '='))
	cp++;

#ifndef WIN32
#define max(a,b) ((a > b) ? (a) : (b))
#endif

    if (g_ascii_strncasecmp(bfr, var, max(strlen(var), cp - bfr)))
	return(0);			/* var is not the var in
					   bfr ==> no match */

    cp = strchr(bfr, '=');
    if (!cp)
	return(0);
    cp++;
    while (*cp && isspace(*cp))		/* space up to variable value */
	cp++;

    return (cp - bfr);			/* return index */
}
