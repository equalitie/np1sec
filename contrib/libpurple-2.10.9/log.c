/**
 * @file log.c Logging API
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"
#include "account.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "internal.h"
#include "log.h"
#include "prefs.h"
#include "util.h"
#include "stringref.h"
#include "imgstore.h"
#include "time.h"

static GSList *loggers = NULL;

static PurpleLogLogger *html_logger;
static PurpleLogLogger *txt_logger;
static PurpleLogLogger *old_logger;

struct _purple_logsize_user {
	char *name;
	PurpleAccount *account;
};
static GHashTable *logsize_users = NULL;
static GHashTable *logsize_users_decayed = NULL;

static void log_get_log_sets_common(GHashTable *sets);

static gsize html_logger_write(PurpleLog *log, PurpleMessageFlags type,
							  const char *from, time_t time, const char *message);
static void html_logger_finalize(PurpleLog *log);
static GList *html_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account);
static GList *html_logger_list_syslog(PurpleAccount *account);
static char *html_logger_read(PurpleLog *log, PurpleLogReadFlags *flags);
static int html_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account);

static GList *old_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account);
static int old_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account);
static char * old_logger_read (PurpleLog *log, PurpleLogReadFlags *flags);
static int old_logger_size (PurpleLog *log);
static void old_logger_get_log_sets(PurpleLogSetCallback cb, GHashTable *sets);
static void old_logger_finalize(PurpleLog *log);

static gsize txt_logger_write(PurpleLog *log,
							 PurpleMessageFlags type,
							 const char *from, time_t time, const char *message);
static void txt_logger_finalize(PurpleLog *log);
static GList *txt_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account);
static GList *txt_logger_list_syslog(PurpleAccount *account);
static char *txt_logger_read(PurpleLog *log, PurpleLogReadFlags *flags);
static int txt_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account);

/**************************************************************************
 * PUBLIC LOGGING FUNCTIONS ***********************************************
 **************************************************************************/

PurpleLog *purple_log_new(PurpleLogType type, const char *name, PurpleAccount *account,
                      PurpleConversation *conv, time_t time, const struct tm *tm)
{
	PurpleLog *log;

	/* IMPORTANT: Make sure to initialize all the members of PurpleLog */
	log = g_slice_new(PurpleLog);
	PURPLE_DBUS_REGISTER_POINTER(log, PurpleLog);

	log->type = type;
	log->name = g_strdup(purple_normalize(account, name));
	log->account = account;
	log->conv = conv;
	log->time = time;
	log->logger = purple_log_logger_get();
	log->logger_data = NULL;

	if (tm == NULL)
		log->tm = NULL;
	else
	{
		/* There's no need to zero this as we immediately do a direct copy. */
		log->tm = g_slice_new(struct tm);

		*(log->tm) = *tm;

#ifdef HAVE_STRUCT_TM_TM_ZONE
		/* XXX: This is so wrong... */
		if (log->tm->tm_zone != NULL)
		{
			char *tmp = g_locale_from_utf8(log->tm->tm_zone, -1, NULL, NULL, NULL);
			if (tmp != NULL)
				log->tm->tm_zone = tmp;
			else
				/* Just shove the UTF-8 bytes in and hope... */
				log->tm->tm_zone = g_strdup(log->tm->tm_zone);
		}
#endif
	}

	if (log->logger && log->logger->create)
		log->logger->create(log);
	return log;
}

void purple_log_free(PurpleLog *log)
{
	g_return_if_fail(log);
	if (log->logger && log->logger->finalize)
		log->logger->finalize(log);
	g_free(log->name);

	if (log->tm != NULL)
	{
#ifdef HAVE_STRUCT_TM_TM_ZONE
		/* XXX: This is so wrong... */
		g_free((char *)log->tm->tm_zone);
#endif
		g_slice_free(struct tm, log->tm);
	}

	PURPLE_DBUS_UNREGISTER_POINTER(log);
	g_slice_free(PurpleLog, log);
}

void purple_log_write(PurpleLog *log, PurpleMessageFlags type,
		    const char *from, time_t time, const char *message)
{
	struct _purple_logsize_user *lu;
	gsize written, total = 0;
	gpointer ptrsize;

	g_return_if_fail(log);
	g_return_if_fail(log->logger);
	g_return_if_fail(log->logger->write);

	written = (log->logger->write)(log, type, from, time, message);

	lu = g_new(struct _purple_logsize_user, 1);

	lu->name = g_strdup(purple_normalize(log->account, log->name));
	lu->account = log->account;

	if(g_hash_table_lookup_extended(logsize_users, lu, NULL, &ptrsize)) {
		char *tmp = lu->name;

		total = GPOINTER_TO_INT(ptrsize);
		total += written;
		g_hash_table_replace(logsize_users, lu, GINT_TO_POINTER(total));

		/* The hash table takes ownership of lu, so create a new one
		 * for the logsize_users_decayed check below. */
		lu = g_new(struct _purple_logsize_user, 1);
		lu->name = g_strdup(tmp);
		lu->account = log->account;
	}

	if(g_hash_table_lookup_extended(logsize_users_decayed, lu, NULL, &ptrsize)) {
		total = GPOINTER_TO_INT(ptrsize);
		total += written;
		g_hash_table_replace(logsize_users_decayed, lu, GINT_TO_POINTER(total));
	} else {
		g_free(lu->name);
		g_free(lu);
	}
}

char *purple_log_read(PurpleLog *log, PurpleLogReadFlags *flags)
{
	PurpleLogReadFlags mflags;
	g_return_val_if_fail(log && log->logger, NULL);
	if (log->logger->read) {
		char *ret = (log->logger->read)(log, flags ? flags : &mflags);
		purple_str_strip_char(ret, '\r');
		return ret;
	}
	return g_strdup(_("<b><font color=\"red\">The logger has no read function</font></b>"));
}

int purple_log_get_size(PurpleLog *log)
{
	g_return_val_if_fail(log && log->logger, 0);

	if (log->logger->size)
		return log->logger->size(log);
	return 0;
}

static guint _purple_logsize_user_hash(struct _purple_logsize_user *lu)
{
	return g_str_hash(lu->name);
}

static guint _purple_logsize_user_equal(struct _purple_logsize_user *lu1,
		struct _purple_logsize_user *lu2)
{
	return (lu1->account == lu2->account && purple_strequal(lu1->name, lu2->name));
}

static void _purple_logsize_user_free_key(struct _purple_logsize_user *lu)
{
	g_free(lu->name);
	g_free(lu);
}

int purple_log_get_total_size(PurpleLogType type, const char *name, PurpleAccount *account)
{
	gpointer ptrsize;
	int size = 0;
	GSList *n;
	struct _purple_logsize_user *lu;

	lu = g_new(struct _purple_logsize_user, 1);
	lu->name = g_strdup(purple_normalize(account, name));
	lu->account = account;

	if(g_hash_table_lookup_extended(logsize_users, lu, NULL, &ptrsize)) {
		size = GPOINTER_TO_INT(ptrsize);
		g_free(lu->name);
		g_free(lu);
	} else {
		for (n = loggers; n; n = n->next) {
			PurpleLogLogger *logger = n->data;

			if(logger->total_size){
				size += (logger->total_size)(type, name, account);
			} else if(logger->list) {
				GList *logs = (logger->list)(type, name, account);
				int this_size = 0;

				while (logs) {
					PurpleLog *log = (PurpleLog*)(logs->data);
					this_size += purple_log_get_size(log);
					purple_log_free(log);
					logs = g_list_delete_link(logs, logs);
				}

				size += this_size;
			}
		}

		g_hash_table_replace(logsize_users, lu, GINT_TO_POINTER(size));
	}
	return size;
}

gint purple_log_get_activity_score(PurpleLogType type, const char *name, PurpleAccount *account)
{
	gpointer ptrscore;
	int score;
	GSList *n;
	struct _purple_logsize_user *lu;
	time_t now;
	time(&now);

	lu = g_new(struct _purple_logsize_user, 1);
	lu->name = g_strdup(purple_normalize(account, name));
	lu->account = account;

	if(g_hash_table_lookup_extended(logsize_users_decayed, lu, NULL, &ptrscore)) {
		score = GPOINTER_TO_INT(ptrscore);
		g_free(lu->name);
		g_free(lu);
	} else {
		double score_double = 0.0;
		for (n = loggers; n; n = n->next) {
			PurpleLogLogger *logger = n->data;

			if(logger->list) {
				GList *logs = (logger->list)(type, name, account);

				while (logs) {
					PurpleLog *log = (PurpleLog*)(logs->data);
					/* Activity score counts bytes in the log, exponentially
					   decayed with a half-life of 14 days. */
					score_double += purple_log_get_size(log) *
						pow(0.5, difftime(now, log->time)/1209600.0);
					purple_log_free(log);
					logs = g_list_delete_link(logs, logs);
				}
			}
		}

		score = (gint) ceil(score_double);
		g_hash_table_replace(logsize_users_decayed, lu, GINT_TO_POINTER(score));
	}
	return score;
}

gboolean purple_log_is_deletable(PurpleLog *log)
{
	g_return_val_if_fail(log != NULL, FALSE);
	g_return_val_if_fail(log->logger != NULL, FALSE);

	if (log->logger->remove == NULL)
		return FALSE;

	if (log->logger->is_deletable != NULL)
		return log->logger->is_deletable(log);

	return TRUE;
}

gboolean purple_log_delete(PurpleLog *log)
{
	g_return_val_if_fail(log != NULL, FALSE);
	g_return_val_if_fail(log->logger != NULL, FALSE);

	if (log->logger->remove != NULL)
		return log->logger->remove(log);

	return FALSE;
}

char *
purple_log_get_log_dir(PurpleLogType type, const char *name, PurpleAccount *account)
{
	PurplePlugin *prpl;
	PurplePluginProtocolInfo *prpl_info;
	const char *prpl_name;
	char *acct_name;
	const char *target;
	char *dir;

	prpl = purple_find_prpl(purple_account_get_protocol_id(account));
	if (!prpl)
		return NULL;
	prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);
	prpl_name = prpl_info->list_icon(account, NULL);

	acct_name = g_strdup(purple_escape_filename(purple_normalize(account,
				purple_account_get_username(account))));

	if (type == PURPLE_LOG_CHAT) {
		char *temp = g_strdup_printf("%s.chat", purple_normalize(account, name));
		target = purple_escape_filename(temp);
		g_free(temp);
	} else if(type == PURPLE_LOG_SYSTEM) {
		target = ".system";
	} else {
		target = purple_escape_filename(purple_normalize(account, name));
	}

	dir = g_build_filename(purple_user_dir(), "logs", prpl_name, acct_name, target, NULL);

	g_free(acct_name);

	return dir;
}

/****************************************************************************
 * LOGGER FUNCTIONS *********************************************************
 ****************************************************************************/

static PurpleLogLogger *current_logger = NULL;

static void logger_pref_cb(const char *name, PurplePrefType type,
						   gconstpointer value, gpointer data)
{
	PurpleLogLogger *logger;
	GSList *l = loggers;
	while (l) {
		logger = l->data;
		if (purple_strequal(logger->id, value)) {
			purple_log_logger_set(logger);
			return;
		}
		l = l->next;
	}
	purple_log_logger_set(txt_logger);
}


PurpleLogLogger *purple_log_logger_new(const char *id, const char *name, int functions, ...)
{
#if 0
				void(*create)(PurpleLog *),
				gsize(*write)(PurpleLog *, PurpleMessageFlags, const char *, time_t, const char *),
				void(*finalize)(PurpleLog *),
				GList*(*list)(PurpleLogType type, const char*, PurpleAccount*),
				char*(*read)(PurpleLog*, PurpleLogReadFlags*),
				int(*size)(PurpleLog*),
				int(*total_size)(PurpleLogType type, const char *name, PurpleAccount *account),
				GList*(*list_syslog)(PurpleAccount *account),
				void(*get_log_sets)(PurpleLogSetCallback cb, GHashTable *sets),
				gboolean(*remove)(PurpleLog *log),
				gboolean(*is_deletable)(PurpleLog *log))
#endif
	PurpleLogLogger *logger;
	va_list args;

	g_return_val_if_fail(id != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(functions >= 1, NULL);

	logger = g_new0(PurpleLogLogger, 1);
	logger->id = g_strdup(id);
	logger->name = g_strdup(name);

	va_start(args, functions);

	if (functions >= 1)
		logger->create = va_arg(args, void *);
	if (functions >= 2)
		logger->write = va_arg(args, void *);
	if (functions >= 3)
		logger->finalize = va_arg(args, void *);
	if (functions >= 4)
		logger->list = va_arg(args, void *);
	if (functions >= 5)
		logger->read = va_arg(args, void *);
	if (functions >= 6)
		logger->size = va_arg(args, void *);
	if (functions >= 7)
		logger->total_size = va_arg(args, void *);
	if (functions >= 8)
		logger->list_syslog = va_arg(args, void *);
	if (functions >= 9)
		logger->get_log_sets = va_arg(args, void *);
	if (functions >= 10)
		logger->remove = va_arg(args, void *);
	if (functions >= 11)
		logger->is_deletable = va_arg(args, void *);

	if (functions >= 12)
		purple_debug_info("log", "Dropping new functions for logger: %s (%s)\n", name, id);

	va_end(args);

	return logger;
}

void purple_log_logger_free(PurpleLogLogger *logger)
{
	g_free(logger->name);
	g_free(logger->id);
	g_free(logger);
}

void purple_log_logger_add (PurpleLogLogger *logger)
{
	g_return_if_fail(logger);
	if (g_slist_find(loggers, logger))
		return;
	loggers = g_slist_append(loggers, logger);
	if (purple_strequal(purple_prefs_get_string("/purple/logging/format"), logger->id)) {
		purple_prefs_trigger_callback("/purple/logging/format");
	}
}

void purple_log_logger_remove (PurpleLogLogger *logger)
{
	g_return_if_fail(logger);
	loggers = g_slist_remove(loggers, logger);
}

void purple_log_logger_set (PurpleLogLogger *logger)
{
	g_return_if_fail(logger);
	current_logger = logger;
}

PurpleLogLogger *purple_log_logger_get()
{
	return current_logger;
}

GList *purple_log_logger_get_options(void)
{
	GSList *n;
	GList *list = NULL;
	PurpleLogLogger *data;

	for (n = loggers; n; n = n->next) {
		data = n->data;
		if (!data->write)
			continue;
		list = g_list_append(list, data->name);
		list = g_list_append(list, data->id);
	}

	return list;
}

gint purple_log_compare(gconstpointer y, gconstpointer z)
{
	const PurpleLog *a = y;
	const PurpleLog *b = z;

	return b->time - a->time;
}

GList *purple_log_get_logs(PurpleLogType type, const char *name, PurpleAccount *account)
{
	GList *logs = NULL;
	GSList *n;
	for (n = loggers; n; n = n->next) {
		PurpleLogLogger *logger = n->data;
		if (!logger->list)
			continue;
		logs = g_list_concat(logger->list(type, name, account), logs);
	}

	return g_list_sort(logs, purple_log_compare);
}

gint purple_log_set_compare(gconstpointer y, gconstpointer z)
{
	const PurpleLogSet *a = y;
	const PurpleLogSet *b = z;
	gint ret = 0;

	/* This logic seems weird at first...
	 * If either account is NULL, we pretend the accounts are
	 * equal. This allows us to detect duplicates that will
	 * exist if one logger knows the account and another
	 * doesn't. */
	if (a->account != NULL && b->account != NULL) {
		ret = strcmp(purple_account_get_username(a->account), purple_account_get_username(b->account));
		if (ret != 0)
			return ret;
	}

	ret = strcmp(a->normalized_name, b->normalized_name);
	if (ret != 0)
		return ret;

	return (gint)b->type - (gint)a->type;
}

static guint
log_set_hash(gconstpointer key)
{
	const PurpleLogSet *set = key;

	/* The account isn't hashed because we need PurpleLogSets with NULL accounts
	 * to be found when we search by a PurpleLogSet that has a non-NULL account
	 * but the same type and name. */
	return g_int_hash(&set->type) + g_str_hash(set->name);
}

static gboolean
log_set_equal(gconstpointer a, gconstpointer b)
{
	/* I realize that the choices made for GList and GHashTable
	 * make sense for those data types, but I wish the comparison
	 * functions were compatible. */
	return !purple_log_set_compare(a, b);
}

static void
log_add_log_set_to_hash(GHashTable *sets, PurpleLogSet *set)
{
	PurpleLogSet *existing_set = g_hash_table_lookup(sets, set);

	if (existing_set == NULL)
		g_hash_table_insert(sets, set, set);
	else if (existing_set->account == NULL && set->account != NULL)
		g_hash_table_replace(sets, set, set);
	else
		purple_log_set_free(set);
}

GHashTable *purple_log_get_log_sets(void)
{
	GSList *n;
	GHashTable *sets = g_hash_table_new_full(log_set_hash, log_set_equal,
											 (GDestroyNotify)purple_log_set_free, NULL);

	/* Get the log sets from all the loggers. */
	for (n = loggers; n; n = n->next) {
		PurpleLogLogger *logger = n->data;

		if (!logger->get_log_sets)
			continue;

		logger->get_log_sets(log_add_log_set_to_hash, sets);
	}

	log_get_log_sets_common(sets);

	/* Return the GHashTable of unique PurpleLogSets. */
	return sets;
}

void purple_log_set_free(PurpleLogSet *set)
{
	g_return_if_fail(set != NULL);

	g_free(set->name);
	if (set->normalized_name != set->name)
		g_free(set->normalized_name);

	g_slice_free(PurpleLogSet, set);
}

GList *purple_log_get_system_logs(PurpleAccount *account)
{
	GList *logs = NULL;
	GSList *n;
	for (n = loggers; n; n = n->next) {
		PurpleLogLogger *logger = n->data;
		if (!logger->list_syslog)
			continue;
		logs = g_list_concat(logger->list_syslog(account), logs);
	}

	return g_list_sort(logs, purple_log_compare);
}

/****************************************************************************
 * LOG SUBSYSTEM ************************************************************
 ****************************************************************************/

void *
purple_log_get_handle(void)
{
	static int handle;

	return &handle;
}

void purple_log_init(void)
{
	void *handle = purple_log_get_handle();

	purple_prefs_add_none("/purple/logging");
	purple_prefs_add_bool("/purple/logging/log_ims", TRUE);
	purple_prefs_add_bool("/purple/logging/log_chats", TRUE);
	purple_prefs_add_bool("/purple/logging/log_system", FALSE);

	purple_prefs_add_string("/purple/logging/format", "html");

	html_logger = purple_log_logger_new("html", _("HTML"), 11,
									  NULL,
									  html_logger_write,
									  html_logger_finalize,
									  html_logger_list,
									  html_logger_read,
									  purple_log_common_sizer,
									  html_logger_total_size,
									  html_logger_list_syslog,
									  NULL,
									  purple_log_common_deleter,
									  purple_log_common_is_deletable);
	purple_log_logger_add(html_logger);

	txt_logger = purple_log_logger_new("txt", _("Plain text"), 11,
									 NULL,
									 txt_logger_write,
									 txt_logger_finalize,
									 txt_logger_list,
									 txt_logger_read,
									 purple_log_common_sizer,
									 txt_logger_total_size,
									 txt_logger_list_syslog,
									 NULL,
									 purple_log_common_deleter,
									 purple_log_common_is_deletable);
	purple_log_logger_add(txt_logger);

	old_logger = purple_log_logger_new("old", _("Old flat format"), 9,
									 NULL,
									 NULL,
									 old_logger_finalize,
									 old_logger_list,
									 old_logger_read,
									 old_logger_size,
									 old_logger_total_size,
									 NULL,
									 old_logger_get_log_sets);
	purple_log_logger_add(old_logger);

	purple_signal_register(handle, "log-timestamp",
#if SIZEOF_TIME_T == 4
	                     purple_marshal_POINTER__POINTER_INT_BOOLEAN,
#elif SIZEOF_TIME_T == 8
			     purple_marshal_POINTER__POINTER_INT64_BOOLEAN,
#else
#error Unknown size of time_t
#endif
	                     purple_value_new(PURPLE_TYPE_STRING), 3,
	                     purple_value_new(PURPLE_TYPE_SUBTYPE,
	                                    PURPLE_SUBTYPE_LOG),
#if SIZEOF_TIME_T == 4
	                     purple_value_new(PURPLE_TYPE_INT),
#elif SIZEOF_TIME_T == 8
	                     purple_value_new(PURPLE_TYPE_INT64),
#else
# error Unknown size of time_t
#endif
	                     purple_value_new(PURPLE_TYPE_BOOLEAN));

	purple_prefs_connect_callback(NULL, "/purple/logging/format",
							    logger_pref_cb, NULL);
	purple_prefs_trigger_callback("/purple/logging/format");

	logsize_users = g_hash_table_new_full((GHashFunc)_purple_logsize_user_hash,
			(GEqualFunc)_purple_logsize_user_equal,
			(GDestroyNotify)_purple_logsize_user_free_key, NULL);
	logsize_users_decayed = g_hash_table_new_full((GHashFunc)_purple_logsize_user_hash,
				(GEqualFunc)_purple_logsize_user_equal,
				(GDestroyNotify)_purple_logsize_user_free_key, NULL);
}

void
purple_log_uninit(void)
{
	purple_signals_unregister_by_instance(purple_log_get_handle());

	purple_log_logger_remove(html_logger);
	purple_log_logger_free(html_logger);
	html_logger = NULL;

	purple_log_logger_remove(txt_logger);
	purple_log_logger_free(txt_logger);
	txt_logger = NULL;

	purple_log_logger_remove(old_logger);
	purple_log_logger_free(old_logger);
	old_logger = NULL;

	g_hash_table_destroy(logsize_users);
	g_hash_table_destroy(logsize_users_decayed);
}

/****************************************************************************
 * LOGGERS ******************************************************************
 ****************************************************************************/

static char *log_get_timestamp(PurpleLog *log, time_t when)
{
	gboolean show_date;
	char *date;
	struct tm *tm;

	show_date = (log->type == PURPLE_LOG_SYSTEM) || (time(NULL) > when + 20*60);

	date = purple_signal_emit_return_1(purple_log_get_handle(),
	                          "log-timestamp",
	                          log, when, show_date);
	if (date != NULL)
		return date;

	tm = localtime(&when);
	if (show_date)
		return g_strdup(purple_date_format_long(tm));
	else
		return g_strdup(purple_time_format(tm));
}

/* NOTE: This can return msg (which you may or may not want to g_free())
 * NOTE: or a newly allocated string which you MUST g_free(). */
static char *
convert_image_tags(const PurpleLog *log, const char *msg)
{
	const char *tmp;
	const char *start;
	const char *end;
	GData *attributes;
	GString *newmsg = NULL;

	tmp = msg;

	while (purple_markup_find_tag("img", tmp, &start, &end, &attributes)) {
		int imgid = 0;
		char *idstr = NULL;

		if (newmsg == NULL)
			newmsg = g_string_new("");

		/* copy any text before the img tag */
		if (tmp < start)
			g_string_append_len(newmsg, tmp, start - tmp);

		if ((idstr = g_datalist_get_data(&attributes, "id")) != NULL)
			imgid = atoi(idstr);

		if (imgid != 0)
		{
			FILE *image_file;
			char *dir;
			PurpleStoredImage *image;
			gconstpointer image_data;
			char *new_filename = NULL;
			char *path = NULL;
			size_t image_byte_count;

			image = purple_imgstore_find_by_id(imgid);
			if (image == NULL)
			{
				/* This should never happen. */
				/* This *does* happen for failed Direct-IMs -DAA */
				g_string_free(newmsg, TRUE);
				g_return_val_if_reached((char *)msg);
			}

			image_data       = purple_imgstore_get_data(image);
			image_byte_count = purple_imgstore_get_size(image);
			dir              = purple_log_get_log_dir(log->type, log->name, log->account);
			new_filename     = purple_util_get_image_filename(image_data, image_byte_count);

			path = g_build_filename(dir, new_filename, NULL);

			/* Only save unique files. */
			if (!g_file_test(path, G_FILE_TEST_EXISTS))
			{
				if ((image_file = g_fopen(path, "wb")) != NULL)
				{
					if (!fwrite(image_data, image_byte_count, 1, image_file))
					{
						purple_debug_error("log", "Error writing %s: %s\n",
						                   path, g_strerror(errno));
						fclose(image_file);

						/* Attempt to not leave half-written files around. */
						unlink(path);
					}
					else
					{
						purple_debug_info("log", "Wrote image file: %s\n", path);
						fclose(image_file);
					}
				}
				else
				{
					purple_debug_error("log", "Unable to create file %s: %s\n",
					                   path, g_strerror(errno));
				}
			}

			/* Write the new image tag */
			g_string_append_printf(newmsg, "<IMG SRC=\"%s\">", new_filename);
			g_free(new_filename);
			g_free(path);
		}

		/* Continue from the end of the tag */
		tmp = end + 1;
	}

	if (newmsg == NULL)
	{
		/* No images were found to change. */
		return (char *)msg;
	}

	/* Append any remaining message data */
	g_string_append(newmsg, tmp);

	return g_string_free(newmsg, FALSE);
}

void purple_log_common_writer(PurpleLog *log, const char *ext)
{
	PurpleLogCommonLoggerData *data = log->logger_data;

	if (data == NULL)
	{
		/* This log is new */
		char *dir;
		struct tm *tm;
		const char *tz;
		const char *date;
		char *filename;
		char *path;

		dir = purple_log_get_log_dir(log->type, log->name, log->account);
		if (dir == NULL)
			return;

		purple_build_dir (dir, S_IRUSR | S_IWUSR | S_IXUSR);

		tm = localtime(&log->time);
		tz = purple_escape_filename(purple_utf8_strftime("%Z", tm));
		date = purple_utf8_strftime("%Y-%m-%d.%H%M%S%z", tm);

		filename = g_strdup_printf("%s%s%s", date, tz, ext ? ext : "");

		path = g_build_filename(dir, filename, NULL);
		g_free(dir);
		g_free(filename);

		log->logger_data = data = g_slice_new0(PurpleLogCommonLoggerData);

		data->file = g_fopen(path, "a");
		if (data->file == NULL)
		{
			purple_debug(PURPLE_DEBUG_ERROR, "log",
					"Could not create log file %s\n", path);

			if (log->conv != NULL)
				purple_conversation_write(log->conv, NULL, _("Logging of this conversation failed."),
										PURPLE_MESSAGE_ERROR, time(NULL));

			g_free(path);
			return;
		}
		g_free(path);
	}
}

GList *purple_log_common_lister(PurpleLogType type, const char *name, PurpleAccount *account, const char *ext, PurpleLogLogger *logger)
{
	GDir *dir;
	GList *list = NULL;
	const char *filename;
	char *path;

	if(!account)
		return NULL;

	path = purple_log_get_log_dir(type, name, account);
	if (path == NULL)
		return NULL;

	if (!(dir = g_dir_open(path, 0, NULL)))
	{
		g_free(path);
		return NULL;
	}

	while ((filename = g_dir_read_name(dir)))
	{
		if (purple_str_has_suffix(filename, ext) &&
		    strlen(filename) >= (17 + strlen(ext)))
		{
			PurpleLog *log;
			PurpleLogCommonLoggerData *data;
			struct tm tm;
#if defined (HAVE_TM_GMTOFF) && defined (HAVE_STRUCT_TM_TM_ZONE)
			long tz_off;
			const char *rest, *end;
			time_t stamp = purple_str_to_time(purple_unescape_filename(filename), FALSE, &tm, &tz_off, &rest);

			/* As zero is a valid offset, PURPLE_NO_TZ_OFF means no offset was
			 * provided. See util.h. Yes, it's kinda ugly. */
			if (tz_off != PURPLE_NO_TZ_OFF)
				tm.tm_gmtoff = tz_off - tm.tm_gmtoff;

			if (stamp == 0 || rest == NULL || (end = strchr(rest, '.')) == NULL || strchr(rest, ' ') != NULL)
			{
				log = purple_log_new(type, name, account, NULL, stamp, NULL);
			}
			else
			{
				char *tmp = g_strndup(rest, end - rest);
				tm.tm_zone = tmp;
				log = purple_log_new(type, name, account, NULL, stamp, &tm);
				g_free(tmp);
			}
#else
			time_t stamp = purple_str_to_time(filename, FALSE, &tm, NULL, NULL);

			log = purple_log_new(type, name, account, NULL, stamp, (stamp != 0) ?  &tm : NULL);
#endif

			log->logger = logger;
			log->logger_data = data = g_slice_new0(PurpleLogCommonLoggerData);

			data->path = g_build_filename(path, filename, NULL);
			list = g_list_prepend(list, log);
		}
	}
	g_dir_close(dir);
	g_free(path);
	return list;
}

int purple_log_common_total_sizer(PurpleLogType type, const char *name, PurpleAccount *account, const char *ext)
{
	GDir *dir;
	int size = 0;
	const char *filename;
	char *path;

	if(!account)
		return 0;

	path = purple_log_get_log_dir(type, name, account);
	if (path == NULL)
		return 0;

	if (!(dir = g_dir_open(path, 0, NULL)))
	{
		g_free(path);
		return 0;
	}

	while ((filename = g_dir_read_name(dir)))
	{
		if (purple_str_has_suffix(filename, ext) &&
		    strlen(filename) >= (17 + strlen(ext)))
		{
			char *tmp = g_build_filename(path, filename, NULL);
			struct stat st;
			if (g_stat(tmp, &st))
			{
				purple_debug_error("log", "Error stating log file: %s\n", tmp);
				g_free(tmp);
				continue;
			}
			g_free(tmp);
			size += st.st_size;
		}
	}
	g_dir_close(dir);
	g_free(path);
	return size;
}

int purple_log_common_sizer(PurpleLog *log)
{
	struct stat st;
	PurpleLogCommonLoggerData *data = log->logger_data;

	g_return_val_if_fail(data != NULL, 0);

	if (!data->path || g_stat(data->path, &st))
		st.st_size = 0;

	return st.st_size;
}

/* This will build log sets for all loggers that use the common logger
 * functions because they use the same directory structure. */
static void log_get_log_sets_common(GHashTable *sets)
{
	gchar *log_path = g_build_filename(purple_user_dir(), "logs", NULL);
	GDir *log_dir = g_dir_open(log_path, 0, NULL);
	const gchar *protocol;

	if (log_dir == NULL) {
		g_free(log_path);
		return;
	}

	while ((protocol = g_dir_read_name(log_dir)) != NULL) {
		gchar *protocol_path = g_build_filename(log_path, protocol, NULL);
		GDir *protocol_dir;
		const gchar *username;
		gchar *protocol_unescaped;
		GList *account_iter;
		GList *accounts = NULL;

		if ((protocol_dir = g_dir_open(protocol_path, 0, NULL)) == NULL) {
			g_free(protocol_path);
			continue;
		}

		/* Using g_strdup() to cover the one-in-a-million chance that a
		 * prpl's list_icon function uses purple_unescape_filename(). */
		protocol_unescaped = g_strdup(purple_unescape_filename(protocol));

		/* Find all the accounts for protocol. */
		for (account_iter = purple_accounts_get_all() ; account_iter != NULL ; account_iter = account_iter->next) {
			PurplePlugin *prpl;
			PurplePluginProtocolInfo *prpl_info;

			prpl = purple_find_prpl(purple_account_get_protocol_id((PurpleAccount *)account_iter->data));
			if (!prpl)
				continue;
			prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(prpl);

			if (purple_strequal(protocol_unescaped, prpl_info->list_icon((PurpleAccount *)account_iter->data, NULL)))
				accounts = g_list_prepend(accounts, account_iter->data);
		}
		g_free(protocol_unescaped);

		while ((username = g_dir_read_name(protocol_dir)) != NULL) {
			gchar *username_path = g_build_filename(protocol_path, username, NULL);
			GDir *username_dir;
			const gchar *username_unescaped;
			PurpleAccount *account = NULL;
			gchar *name;

			if ((username_dir = g_dir_open(username_path, 0, NULL)) == NULL) {
				g_free(username_path);
				continue;
			}

			/* Find the account for username in the list of accounts for protocol. */
			username_unescaped = purple_unescape_filename(username);
			for (account_iter = g_list_first(accounts) ; account_iter != NULL ; account_iter = account_iter->next) {
				if (purple_strequal(((PurpleAccount *)account_iter->data)->username, username_unescaped)) {
					account = account_iter->data;
					break;
				}
			}

			/* Don't worry about the cast, name will point to dynamically allocated memory shortly. */
			while ((name = (gchar *)g_dir_read_name(username_dir)) != NULL) {
				size_t len;
				PurpleLogSet *set;

				/* IMPORTANT: Always initialize all members of PurpleLogSet */
				set = g_slice_new(PurpleLogSet);

				/* Unescape the filename. */
				name = g_strdup(purple_unescape_filename(name));

				/* Get the (possibly new) length of name. */
				len = strlen(name);

				set->type = PURPLE_LOG_IM;
				set->name = name;
				set->account = account;
				/* set->buddy is always set below */
				set->normalized_name = g_strdup(purple_normalize(account, name));

				/* Check for .chat or .system at the end of the name to determine the type. */
				if (len >= 7) {
					gchar *tmp = &name[len - 7];
					if (purple_strequal(tmp, ".system")) {
						set->type = PURPLE_LOG_SYSTEM;
						*tmp = '\0';
					}
				}
				if (len > 5) {
					gchar *tmp = &name[len - 5];
					if (purple_strequal(tmp, ".chat")) {
						set->type = PURPLE_LOG_CHAT;
						*tmp = '\0';
					}
				}

				/* Determine if this (account, name) combination exists as a buddy. */
				if (account != NULL && *name != '\0')
					set->buddy = (purple_find_buddy(account, name) != NULL);
				else
					set->buddy = FALSE;

				log_add_log_set_to_hash(sets, set);
			}
			g_free(username_path);
			g_dir_close(username_dir);
		}
		g_free(protocol_path);
		g_list_free(accounts);
		g_dir_close(protocol_dir);
	}
	g_free(log_path);
	g_dir_close(log_dir);
}

gboolean purple_log_common_deleter(PurpleLog *log)
{
	PurpleLogCommonLoggerData *data;
	int ret;

	g_return_val_if_fail(log != NULL, FALSE);

	data = log->logger_data;
	if (data == NULL)
		return FALSE;

	if (data->path == NULL)
		return FALSE;

	ret = g_unlink(data->path);
	if (ret == 0)
		return TRUE;
	else if (ret == -1)
	{
		purple_debug_error("log", "Failed to delete: %s - %s\n", data->path, g_strerror(errno));
	}
	else
	{
		/* I'm not sure that g_unlink() will ever return
		 * something other than 0 or -1. -- rlaager */
		purple_debug_error("log", "Failed to delete: %s\n", data->path);
	}

	return FALSE;
}

gboolean purple_log_common_is_deletable(PurpleLog *log)
{
	PurpleLogCommonLoggerData *data;
#ifndef _WIN32
	gchar *dirname;
#endif

	g_return_val_if_fail(log != NULL, FALSE);

	data = log->logger_data;
	if (data == NULL)
		return FALSE;

	if (data->path == NULL)
		return FALSE;

#ifndef _WIN32
	dirname = g_path_get_dirname(data->path);
	if (g_access(dirname, W_OK) == 0)
	{
		g_free(dirname);
		return TRUE;
	}
	purple_debug_info("log", "access(%s) failed: %s\n", dirname, g_strerror(errno));
	g_free(dirname);
#else
	/* Unless and until someone writes equivalent win32 code,
	 * we'll assume the file is deletable. */
	return TRUE;
#endif

	return FALSE;
}

static char *process_txt_log(char *txt, char *to_free)
{
	char *tmp;

	/* The to_free argument allows us to save a
	 * g_strdup() in some cases. */

	if (to_free == NULL)
		to_free = txt;

	/* g_markup_escape_text requires valid UTF-8 */
	if (!g_utf8_validate(txt, -1, NULL))
	{
		tmp = purple_utf8_salvage(txt);
		g_free(to_free);
		to_free = txt = tmp;
	}

	tmp = g_markup_escape_text(txt, -1);
	g_free(to_free);
	txt = purple_markup_linkify(tmp);
	g_free(tmp);

	return txt;
}

#if 0 /* Maybe some other time. */
/****************
 ** XML LOGGER **
 ****************/

static const char *str_from_msg_type (PurpleMessageFlags type)
{

		return "";

}

static void xml_logger_write(PurpleLog *log,
			     PurpleMessageFlags type,
			     const char *from, time_t time, const char *message)
{
	char *xhtml = NULL;

	if (!log->logger_data) {
		/* This log is new.  We could use the loggers 'new' function, but
		 * creating a new file there would result in empty files in the case
		 * that you open a convo with someone, but don't say anything.
		 */
		struct tm *tm;
		const char *tz;
		const char *date;
		char *dir = purple_log_get_log_dir(log->type, log->name, log->account);
		char *name;
		char *filename;

		if (dir == NULL)
			return;

		tm = localtime(&log->time);
		tz = purple_escape_filename(purple_utf8_strftime("%Z", tm);
		date = purple_utf8_strftime("%Y-%m-%d.%H%M%S%z", tm);

		name = g_strdup_printf("%s%s%s", date, tz, ext ? ext : "");

		purple_build_dir (dir, S_IRUSR | S_IWUSR | S_IXUSR);

		filename = g_build_filename(dir, name, NULL);
		g_free(dir);
		g_free(name);

		log->logger_data = g_fopen(filename, "a");
		if (!log->logger_data) {
			purple_debug(PURPLE_DEBUG_ERROR, "log", "Could not create log file %s\n", filename);
			g_free(filename);
			return;
		}
		g_free(filename);
		fprintf(log->logger_data, "<?xml version='1.0' encoding='UTF-8' ?>\n"
			"<?xml-stylesheet href='file:///usr/src/web/htdocs/log-stylesheet.xsl' type='text/xml' ?>\n");

		date = purple_utf8_strftime("%Y-%m-%d %H:%M:%S", localtime(&log->time));
		fprintf(log->logger_data, "<conversation time='%s' screenname='%s' protocol='%s'>\n",
			date, log->name, prpl);
	}

	/* if we can't write to the file, give up before we hurt ourselves */
	if(!data->file)
		return;

	date = log_get_timestamp(log, time);

	purple_markup_html_to_xhtml(message, &xhtml, NULL);
	if (from)
		fprintf(log->logger_data, "<message %s %s from='%s' time='%s'>%s</message>\n",
			str_from_msg_type(type),
			type & PURPLE_MESSAGE_SEND ? "direction='sent'" :
			type & PURPLE_MESSAGE_RECV ? "direction='received'" : "",
			from, date, xhtml);
	else
		fprintf(log->logger_data, "<message %s %s time='%s'>%s</message>\n",
			str_from_msg_type(type),
			type & PURPLE_MESSAGE_SEND ? "direction='sent'" :
			type & PURPLE_MESSAGE_RECV ? "direction='received'" : "",
			date, xhtml):
	fflush(log->logger_data);
	g_free(date);
	g_free(xhtml);
}

 static void xml_logger_finalize(PurpleLog *log)
{
	if (log->logger_data) {
		fprintf(log->logger_data, "</conversation>\n");
		fclose(log->logger_data);
		log->logger_data = NULL;
	}
}

static GList *xml_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account)
{
	return purple_log_common_lister(type, sn, account, ".xml", &xml_logger);
}

static PurpleLogLogger xml_logger =  {
	N_("XML"), "xml",
	NULL,
	xml_logger_write,
	xml_logger_finalize,
	xml_logger_list,
	NULL,
	NULL,
	NULL
};
#endif

/****************************
 ** HTML LOGGER *************
 ****************************/

static gsize html_logger_write(PurpleLog *log, PurpleMessageFlags type,
							  const char *from, time_t time, const char *message)
{
	char *msg_fixed;
	char *image_corrected_msg;
	char *date;
	char *header;
	char *escaped_from;
	PurplePlugin *plugin = purple_find_prpl(purple_account_get_protocol_id(log->account));
	PurpleLogCommonLoggerData *data = log->logger_data;
	gsize written = 0;

	if(!data) {
		const char *prpl =
			PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->list_icon(log->account, NULL);
		const char *date;
		purple_log_common_writer(log, ".html");

		data = log->logger_data;

		/* if we can't write to the file, give up before we hurt ourselves */
		if(!data->file)
			return 0;

		date = purple_date_format_full(localtime(&log->time));

		written += fprintf(data->file, "<html><head>");
		written += fprintf(data->file, "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">");
		written += fprintf(data->file, "<title>");
		if (log->type == PURPLE_LOG_SYSTEM)
			header = g_strdup_printf("System log for account %s (%s) connected at %s",
					purple_account_get_username(log->account), prpl, date);
		else
			header = g_strdup_printf("Conversation with %s at %s on %s (%s)",
					log->name, date, purple_account_get_username(log->account), prpl);

		written += fprintf(data->file, "%s", header);
		written += fprintf(data->file, "</title></head><body>");
		written += fprintf(data->file, "<h3>%s</h3>\n", header);
		g_free(header);
	}

	/* if we can't write to the file, give up before we hurt ourselves */
	if(!data->file)
		return 0;

	escaped_from = g_markup_escape_text(from, -1);

	image_corrected_msg = convert_image_tags(log, message);
	purple_markup_html_to_xhtml(image_corrected_msg, &msg_fixed, NULL);

	/* Yes, this breaks encapsulation.  But it's a static function and
	 * this saves a needless strdup(). */
	if (image_corrected_msg != message)
		g_free(image_corrected_msg);

	date = log_get_timestamp(log, time);

	if(log->type == PURPLE_LOG_SYSTEM){
		written += fprintf(data->file, "---- %s @ %s ----<br/>\n", msg_fixed, date);
	} else {
		if (type & PURPLE_MESSAGE_SYSTEM)
			written += fprintf(data->file, "<font size=\"2\">(%s)</font><b> %s</b><br/>\n", date, msg_fixed);
		else if (type & PURPLE_MESSAGE_RAW)
			written += fprintf(data->file, "<font size=\"2\">(%s)</font> %s<br/>\n", date, msg_fixed);
		else if (type & PURPLE_MESSAGE_ERROR)
			written += fprintf(data->file, "<font color=\"#FF0000\"><font size=\"2\">(%s)</font><b> %s</b></font><br/>\n", date, msg_fixed);
		else if (type & PURPLE_MESSAGE_WHISPER)
			written += fprintf(data->file, "<font color=\"#6C2585\"><font size=\"2\">(%s)</font><b> %s:</b></font> %s<br/>\n",
					date, escaped_from, msg_fixed);
		else if (type & PURPLE_MESSAGE_AUTO_RESP) {
			if (type & PURPLE_MESSAGE_SEND)
				written += fprintf(data->file, _("<font color=\"#16569E\"><font size=\"2\">(%s)</font> <b>%s &lt;AUTO-REPLY&gt;:</b></font> %s<br/>\n"), date, escaped_from, msg_fixed);
			else if (type & PURPLE_MESSAGE_RECV)
				written += fprintf(data->file, _("<font color=\"#A82F2F\"><font size=\"2\">(%s)</font> <b>%s &lt;AUTO-REPLY&gt;:</b></font> %s<br/>\n"), date, escaped_from, msg_fixed);
		} else if (type & PURPLE_MESSAGE_RECV) {
			if(purple_message_meify(msg_fixed, -1))
				written += fprintf(data->file, "<font color=\"#062585\"><font size=\"2\">(%s)</font> <b>***%s</b></font> %s<br/>\n",
						date, escaped_from, msg_fixed);
			else
				written += fprintf(data->file, "<font color=\"#A82F2F\"><font size=\"2\">(%s)</font> <b>%s:</b></font> %s<br/>\n",
						date, escaped_from, msg_fixed);
		} else if (type & PURPLE_MESSAGE_SEND) {
			if(purple_message_meify(msg_fixed, -1))
				written += fprintf(data->file, "<font color=\"#062585\"><font size=\"2\">(%s)</font> <b>***%s</b></font> %s<br/>\n",
						date, escaped_from, msg_fixed);
			else
				written += fprintf(data->file, "<font color=\"#16569E\"><font size=\"2\">(%s)</font> <b>%s:</b></font> %s<br/>\n",
						date, escaped_from, msg_fixed);
		} else {
			purple_debug_error("log", "Unhandled message type.\n");
			written += fprintf(data->file, "<font size=\"2\">(%s)</font><b> %s:</b></font> %s<br/>\n",
						date, escaped_from, msg_fixed);
		}
	}
	g_free(date);
	g_free(msg_fixed);
	g_free(escaped_from);
	fflush(data->file);

	return written;
}

static void html_logger_finalize(PurpleLog *log)
{
	PurpleLogCommonLoggerData *data = log->logger_data;
	if (data) {
		if(data->file) {
			fprintf(data->file, "</body></html>\n");
			fclose(data->file);
		}
		g_free(data->path);

		g_slice_free(PurpleLogCommonLoggerData, data);
	}
}

static GList *html_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account)
{
	return purple_log_common_lister(type, sn, account, ".html", html_logger);
}

static GList *html_logger_list_syslog(PurpleAccount *account)
{
	return purple_log_common_lister(PURPLE_LOG_SYSTEM, ".system", account, ".html", html_logger);
}

static char *html_logger_read(PurpleLog *log, PurpleLogReadFlags *flags)
{
	char *read;
	PurpleLogCommonLoggerData *data = log->logger_data;
	*flags = PURPLE_LOG_READ_NO_NEWLINE;
	if (!data || !data->path)
		return g_strdup(_("<font color=\"red\"><b>Unable to find log path!</b></font>"));
	if (g_file_get_contents(data->path, &read, NULL, NULL)) {
		char *minus_header = strchr(read, '\n');

		if (!minus_header)
			return read;

		minus_header = g_strdup(minus_header + 1);
		g_free(read);

		return minus_header;
	}
	return g_strdup_printf(_("<font color=\"red\"><b>Could not read file: %s</b></font>"), data->path);
}

static int html_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account)
{
	return purple_log_common_total_sizer(type, name, account, ".html");
}


/****************************
 ** PLAIN TEXT LOGGER *******
 ****************************/

static gsize txt_logger_write(PurpleLog *log,
							 PurpleMessageFlags type,
							 const char *from, time_t time, const char *message)
{
	char *date;
	PurplePlugin *plugin = purple_find_prpl(purple_account_get_protocol_id(log->account));
	PurpleLogCommonLoggerData *data = log->logger_data;
	char *stripped = NULL;

	gsize written = 0;

	if (data == NULL) {
		/* This log is new.  We could use the loggers 'new' function, but
		 * creating a new file there would result in empty files in the case
		 * that you open a convo with someone, but don't say anything.
		 */
		const char *prpl =
			PURPLE_PLUGIN_PROTOCOL_INFO(plugin)->list_icon(log->account, NULL);
		purple_log_common_writer(log, ".txt");

		data = log->logger_data;

		/* if we can't write to the file, give up before we hurt ourselves */
		if(!data->file)
			return 0;

		if (log->type == PURPLE_LOG_SYSTEM)
			written += fprintf(data->file, "System log for account %s (%s) connected at %s\n",
				purple_account_get_username(log->account), prpl,
				purple_date_format_full(localtime(&log->time)));
		else
			written += fprintf(data->file, "Conversation with %s at %s on %s (%s)\n",
				log->name, purple_date_format_full(localtime(&log->time)),
				purple_account_get_username(log->account), prpl);
	}

	/* if we can't write to the file, give up before we hurt ourselves */
	if(!data->file)
		return 0;

	stripped = purple_markup_strip_html(message);
	date = log_get_timestamp(log, time);

	if(log->type == PURPLE_LOG_SYSTEM){
		written += fprintf(data->file, "---- %s @ %s ----\n", stripped, date);
	} else {
		if (type & PURPLE_MESSAGE_SEND ||
			type & PURPLE_MESSAGE_RECV) {
			if (type & PURPLE_MESSAGE_AUTO_RESP) {
				written += fprintf(data->file, _("(%s) %s <AUTO-REPLY>: %s\n"), date,
						from, stripped);
			} else {
				if(purple_message_meify(stripped, -1))
					written += fprintf(data->file, "(%s) ***%s %s\n", date, from,
							stripped);
				else
					written += fprintf(data->file, "(%s) %s: %s\n", date, from,
							stripped);
			}
		} else if (type & PURPLE_MESSAGE_SYSTEM ||
			type & PURPLE_MESSAGE_ERROR ||
			type & PURPLE_MESSAGE_RAW)
			written += fprintf(data->file, "(%s) %s\n", date, stripped);
		else if (type & PURPLE_MESSAGE_NO_LOG) {
			/* This shouldn't happen */
			g_free(stripped);
			return written;
		} else if (type & PURPLE_MESSAGE_WHISPER)
			written += fprintf(data->file, "(%s) *%s* %s", date, from, stripped);
		else
			written += fprintf(data->file, "(%s) %s%s %s\n", date, from ? from : "",
					from ? ":" : "", stripped);
	}
	g_free(date);
	g_free(stripped);
	fflush(data->file);

	return written;
}

static void txt_logger_finalize(PurpleLog *log)
{
	PurpleLogCommonLoggerData *data = log->logger_data;
	if (data) {
		if(data->file)
			fclose(data->file);
		g_free(data->path);

		g_slice_free(PurpleLogCommonLoggerData, data);
	}
}

static GList *txt_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account)
{
	return purple_log_common_lister(type, sn, account, ".txt", txt_logger);
}

static GList *txt_logger_list_syslog(PurpleAccount *account)
{
	return purple_log_common_lister(PURPLE_LOG_SYSTEM, ".system", account, ".txt", txt_logger);
}

static char *txt_logger_read(PurpleLog *log, PurpleLogReadFlags *flags)
{
	char *read, *minus_header;
	PurpleLogCommonLoggerData *data = log->logger_data;
	*flags = 0;
	if (!data || !data->path)
		return g_strdup(_("<font color=\"red\"><b>Unable to find log path!</b></font>"));
	if (g_file_get_contents(data->path, &read, NULL, NULL)) {
		minus_header = strchr(read, '\n');

		if (minus_header)
			return process_txt_log(minus_header + 1, read);
		else
			return process_txt_log(read, NULL);
	}
	return g_strdup_printf(_("<font color=\"red\"><b>Could not read file: %s</b></font>"), data->path);
}

static int txt_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account)
{
	return purple_log_common_total_sizer(type, name, account, ".txt");
}


/****************
 * OLD LOGGER ***
 ****************/

/* The old logger doesn't write logs, only reads them.  This is to include
 * old logs in the log viewer transparently.
 */

struct old_logger_data {
	PurpleStringref *pathref;
	int offset;
	int length;
};

static GList *old_logger_list(PurpleLogType type, const char *sn, PurpleAccount *account)
{
	char *logfile = g_strdup_printf("%s.log", purple_normalize(account, sn));
	char *pathstr = g_build_filename(purple_user_dir(), "logs", logfile, NULL);
	PurpleStringref *pathref = purple_stringref_new(pathstr);
	struct stat st;
	time_t log_last_modified;
	FILE *index;
	FILE *file;
	int index_fd;
	char *index_tmp;
	char buf[BUF_LONG];
	struct tm tm;
	char month[4];
	struct old_logger_data *data = NULL;
	int logfound = 0;
	int lastoff = 0;
	int newlen;
	time_t lasttime = 0;

	PurpleLog *log = NULL;
	GList *list = NULL;

	g_free(logfile);

	if (g_stat(purple_stringref_value(pathref), &st))
	{
		purple_stringref_unref(pathref);
		g_free(pathstr);
		return NULL;
	}
	else
		log_last_modified = st.st_mtime;

	/* Change the .log extension to .idx */
	strcpy(pathstr + strlen(pathstr) - 3, "idx");

	if (g_stat(pathstr, &st) == 0)
	{
		if (st.st_mtime < log_last_modified)
		{
			purple_debug_warning("log", "Index \"%s\" exists, but is older than the log.\n", pathstr);
		}
		else
		{
			/* The index file exists and is at least as new as the log, so open it. */
			if (!(index = g_fopen(pathstr, "rb")))
			{
				purple_debug_error("log", "Failed to open index file \"%s\" for reading: %s\n",
				                 pathstr, g_strerror(errno));

				/* Fall through so that we'll parse the log file. */
			}
			else
			{
				purple_debug_info("log", "Using index: %s\n", pathstr);
				g_free(pathstr);
				while (fgets(buf, BUF_LONG, index))
				{
					unsigned long idx_time;
					if (sscanf(buf, "%d\t%d\t%lu", &lastoff, &newlen, &idx_time) == 3)
					{
						log = purple_log_new(PURPLE_LOG_IM, sn, account, NULL, -1, NULL);
						log->logger = old_logger;
						log->time = (time_t)idx_time;

						/* IMPORTANT: Always set all members of struct old_logger_data */
						data = g_slice_new(struct old_logger_data);

						data->pathref = purple_stringref_ref(pathref);
						data->offset = lastoff;
						data->length = newlen;

						log->logger_data = data;
						list = g_list_prepend(list, log);
					}
				}
				fclose(index);
				purple_stringref_unref(pathref);

				return list;
			}
		}
	}

	if (!(file = g_fopen(purple_stringref_value(pathref), "rb"))) {
		purple_debug_error("log", "Failed to open log file \"%s\" for reading: %s\n",
		                   purple_stringref_value(pathref), g_strerror(errno));
		purple_stringref_unref(pathref);
		g_free(pathstr);
		return NULL;
	}

	index_tmp = g_strdup_printf("%s.XXXXXX", pathstr);
	if ((index_fd = g_mkstemp(index_tmp)) == -1) {
		purple_debug_error("log", "Failed to open index temp file: %s\n",
		                   g_strerror(errno));
		g_free(pathstr);
		g_free(index_tmp);
		index = NULL;
	} else {
		if ((index = fdopen(index_fd, "wb")) == NULL)
		{
			purple_debug_error("log", "Failed to fdopen() index temp file: %s\n",
			                   g_strerror(errno));
			close(index_fd);
			if (index_tmp != NULL)
			{
				g_unlink(index_tmp);
				g_free(index_tmp);
			}
			g_free(pathstr);
		}
	}

	while (fgets(buf, BUF_LONG, file)) {
		if (strstr(buf, "---- New C") != NULL) {
			int length;
			int offset;
			char convostart[32];
			char *temp = strchr(buf, '@');

			if (temp == NULL || strlen(temp) < 2)
				continue;

			temp++;
			length = strcspn(temp, "-");
			if (length > 31) length = 31;

			offset = ftell(file);

			if (logfound) {
				newlen = offset - lastoff - length;
				if(strstr(buf, "----</H3><BR>")) {
					newlen -=
						sizeof("<HR><BR><H3 Align=Center> ---- New Conversation @ ") +
						sizeof("----</H3><BR>") - 2;
				} else {
					newlen -=
						sizeof("---- New Conversation @ ") + sizeof("----") - 2;
				}

				if(strchr(buf, '\r'))
					newlen--;

				if (newlen != 0) {
					log = purple_log_new(PURPLE_LOG_IM, sn, account, NULL, -1, NULL);
					log->logger = old_logger;
					log->time = lasttime;

					/* IMPORTANT: Always set all members of struct old_logger_data */
					data = g_slice_new(struct old_logger_data);

					data->pathref = purple_stringref_ref(pathref);
					data->offset = lastoff;
					data->length = newlen;

					log->logger_data = data;
					list = g_list_prepend(list, log);

					if (index != NULL)
						fprintf(index, "%d\t%d\t%lu\n", data->offset, data->length, (unsigned long)log->time);
				}
			}

			logfound = 1;
			lastoff = offset;

			g_snprintf(convostart, length, "%s", temp);
			memset(&tm, 0, sizeof(tm));
			sscanf(convostart, "%*s %3s %d %d:%d:%d %d",
			       month, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &tm.tm_year);
			/* Ugly hack, in case current locale is not English */
			if (purple_strequal(month, "Jan")) {
				tm.tm_mon= 0;
			} else if (purple_strequal(month, "Feb")) {
				tm.tm_mon = 1;
			} else if (purple_strequal(month, "Mar")) {
				tm.tm_mon = 2;
			} else if (purple_strequal(month, "Apr")) {
				tm.tm_mon = 3;
			} else if (purple_strequal(month, "May")) {
				tm.tm_mon = 4;
			} else if (purple_strequal(month, "Jun")) {
				tm.tm_mon = 5;
			} else if (purple_strequal(month, "Jul")) {
				tm.tm_mon = 6;
			} else if (purple_strequal(month, "Aug")) {
				tm.tm_mon = 7;
			} else if (purple_strequal(month, "Sep")) {
				tm.tm_mon = 8;
			} else if (purple_strequal(month, "Oct")) {
				tm.tm_mon = 9;
			} else if (purple_strequal(month, "Nov")) {
				tm.tm_mon = 10;
			} else if (purple_strequal(month, "Dec")) {
				tm.tm_mon = 11;
			}
			tm.tm_year -= 1900;
			lasttime = mktime(&tm);
		}
	}

	if (logfound) {
		if ((newlen = ftell(file) - lastoff) != 0) {
			log = purple_log_new(PURPLE_LOG_IM, sn, account, NULL, -1, NULL);
			log->logger = old_logger;
			log->time = lasttime;

			/* IMPORTANT: Always set all members of struct old_logger_data */
			data = g_slice_new(struct old_logger_data);

			data->pathref = purple_stringref_ref(pathref);
			data->offset = lastoff;
			data->length = newlen;

			log->logger_data = data;
			list = g_list_prepend(list, log);

			if (index != NULL)
				fprintf(index, "%d\t%d\t%lu\n", data->offset, data->length, (unsigned long)log->time);
		}
	}

	purple_stringref_unref(pathref);
	fclose(file);
	if (index != NULL)
	{
		fclose(index);

		if (index_tmp == NULL)
		{
			g_free(pathstr);
			g_return_val_if_reached(list);
		}

		if (g_rename(index_tmp, pathstr))
		{
			purple_debug_warning("log", "Failed to rename index temp file \"%s\" to \"%s\": %s\n",
			                   index_tmp, pathstr, g_strerror(errno));
			g_unlink(index_tmp);
		}
		else
			purple_debug_info("log", "Built index: %s\n", pathstr);

		g_free(index_tmp);
		g_free(pathstr);
	}
	return list;
}

static int old_logger_total_size(PurpleLogType type, const char *name, PurpleAccount *account)
{
	char *logfile = g_strdup_printf("%s.log", purple_normalize(account, name));
	char *pathstr = g_build_filename(purple_user_dir(), "logs", logfile, NULL);
	int size;
	struct stat st;

	if (g_stat(pathstr, &st))
		size = 0;
	else
		size = st.st_size;

	g_free(logfile);
	g_free(pathstr);

	return size;
}

static char * old_logger_read (PurpleLog *log, PurpleLogReadFlags *flags)
{
	size_t result;
	struct old_logger_data *data = log->logger_data;
	const char *path = purple_stringref_value(data->pathref);
	FILE *file = g_fopen(path, "rb");
	char *read = g_malloc(data->length + 1);
	fseek(file, data->offset, SEEK_SET);
	result = fread(read, data->length, 1, file);
	if (result != 1)
		purple_debug_error("log", "Unable to read from log file: %s\n", path);
	fclose(file);
	read[data->length] = '\0';
	*flags = 0;
	if (strstr(read, "<BR>"))
	{
		*flags |= PURPLE_LOG_READ_NO_NEWLINE;
		return read;
	}

	return process_txt_log(read, NULL);
}

static int old_logger_size (PurpleLog *log)
{
	struct old_logger_data *data = log->logger_data;
	return data ? data->length : 0;
}

static void old_logger_get_log_sets(PurpleLogSetCallback cb, GHashTable *sets)
{
	char *log_path = g_build_filename(purple_user_dir(), "logs", NULL);
	GDir *log_dir = g_dir_open(log_path, 0, NULL);
	gchar *name;
	PurpleBlistNode *gnode, *cnode, *bnode;

	g_free(log_path);
	if (log_dir == NULL)
		return;

	/* Don't worry about the cast, name will be filled with a dynamically allocated data shortly. */
	while ((name = (gchar *)g_dir_read_name(log_dir)) != NULL) {
		size_t len;
		gchar *ext;
		PurpleLogSet *set;
		gboolean found = FALSE;

		/* Unescape the filename. */
		name = g_strdup(purple_unescape_filename(name));

		/* Get the (possibly new) length of name. */
		len = strlen(name);

		if (len < 5) {
			g_free(name);
			continue;
		}

		/* Make sure we're dealing with a log file. */
		ext = &name[len - 4];
		if (!purple_strequal(ext, ".log")) {
			g_free(name);
			continue;
		}

		/* IMPORTANT: Always set all members of PurpleLogSet */
		set = g_slice_new(PurpleLogSet);

		/* Chat for .chat at the end of the name to determine the type. */
		*ext = '\0';
		set->type = PURPLE_LOG_IM;
		if (len > 9) {
			char *tmp = &name[len - 9];
			if (purple_strequal(tmp, ".chat")) {
				set->type = PURPLE_LOG_CHAT;
				*tmp = '\0';
			}
		}

		set->name = set->normalized_name = name;

		/* Search the buddy list to find the account and to determine if this is a buddy. */
		for (gnode = purple_blist_get_root();
		     !found && gnode != NULL;
		     gnode = purple_blist_node_get_sibling_next(gnode))
		{
			if (!PURPLE_BLIST_NODE_IS_GROUP(gnode))
				continue;

			for (cnode = purple_blist_node_get_first_child(gnode);
			     !found && cnode != NULL;
				 cnode = purple_blist_node_get_sibling_next(cnode))
			{
				if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
					continue;

				for (bnode = purple_blist_node_get_first_child(cnode);
				     !found && bnode != NULL;
				     bnode = purple_blist_node_get_sibling_next(bnode))
				{
					PurpleBuddy *buddy = (PurpleBuddy *)bnode;

					if (purple_strequal(purple_buddy_get_name(buddy), name)) {
						set->account = purple_buddy_get_account(buddy);
						set->buddy = TRUE;
						found = TRUE;
					}
				}
			}
		}

		if (!found)
		{
			set->account = NULL;
			set->buddy = FALSE;
		}

		cb(sets, set);
	}
	g_dir_close(log_dir);
}

static void old_logger_finalize(PurpleLog *log)
{
	struct old_logger_data *data = log->logger_data;
	purple_stringref_unref(data->pathref);
	g_slice_free(struct old_logger_data, data);
}
