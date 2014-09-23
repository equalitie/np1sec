/*
 * Header file for common error description library.
 *
 * Copyright 1988, Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright and distribution info, see the documentation supplied
 * with this package.
 */

#ifndef __COM_ERR_H
#define __COM_ERR_H

#define COM_ERR_BUF_LEN 25

/* Use __STDC__ to guess whether we can use stdarg, prototypes, and const.
 * This is a public header file, so autoconf can't help us here. */
#ifdef __STDC__
# include <stdarg.h>
# define ETP(x) x
# define ETCONST const
#else
# define ETP(x) ()
# define ETCONST
#endif

typedef void (*error_handler_t) ETP((ETCONST char *, long, ETCONST char *,
				     va_list));
extern error_handler_t com_err_hook;
void com_err ETP((ETCONST char *, long, ETCONST char *, ...));
ETCONST char *error_message ETP((long));
ETCONST char *error_message_r ETP((long, char *));
error_handler_t set_com_err_hook ETP((error_handler_t));
error_handler_t reset_com_err_hook ETP((void));

#undef ETP

#endif /* ! defined(__COM_ERR_H) */
