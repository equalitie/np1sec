

/* CFLAGS trumps configure values */


/** default host for the purple plugin. You can specialize a build to
    default to your server by supplying this at compile time */
#ifndef MW_PLUGIN_DEFAULT_HOST
#define MW_PLUGIN_DEFAULT_HOST  ""
#endif
/* "" */


/** default port for the purple plugin. You can specialize a build to
    default to your server by supplying this at compile time */
#ifndef MW_PLUGIN_DEFAULT_PORT
#define MW_PLUGIN_DEFAULT_PORT  1533
#endif
/* 1533 */


/** default encoding for the purple plugin.*/
#ifndef MW_PLUGIN_DEFAULT_ENCODING
#define MW_PLUGIN_DEFAULT_ENCODING "ISO-8859-1"
#endif
/* ISO-8859-1 */
