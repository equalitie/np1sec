#include "module.h"

static void
purple_perl_util_url_cb(PurpleUtilFetchUrlData *url_data, void *user_data,
                        const gchar *url_text, size_t size,
                        const gchar *error_message)
{
	SV *sv = (SV *)user_data;
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);

	XPUSHs(sv_2mortal(newSVpvn(url_text, size)));
	PUTBACK;

	call_sv(sv, G_EVAL | G_SCALAR);
	SPAGAIN;

	/* XXX Make sure this destroys it correctly and that we don't want
	 * something like sv_2mortal(sv) or something else here instead. */
	SvREFCNT_dec(sv);

	PUTBACK;
	FREETMPS;
	LEAVE;
}

static void markup_find_tag_foreach(GQuark key_id, char *data, HV *hv) {
	const char *key = NULL;
	key = g_quark_to_string(key_id);
	hv_store(hv, key, strlen(key), newSVpv(data, 0), 0);
}

MODULE = Purple::Util  PACKAGE = Purple::Util  PREFIX = purple_
PROTOTYPES: ENABLE

gboolean
purple_running_gnome()

gboolean
purple_running_kde()

gboolean
purple_running_osx()

int
purple_build_dir(path, mode)
	const char *path
	int mode

gboolean
purple_email_is_valid(address)
	const char *address

const char *
purple_escape_filename(str)
	const char *str

gchar_own *
purple_fd_get_ip(fd)
	int fd

const gchar *
purple_home_dir()

gchar_own*
purple_message_meify(SV *msg)
	PREINIT:
		char *message = NULL;
		gboolean ret;
		gsize len;
	CODE:
		message = SvPV(msg, len);
		message = g_strndup(message, len);
		ret = purple_message_meify(message, len);
		if(ret) {
			/* message will get g_free()'d later on, since RETVAL is gchar_own* */
			RETVAL = message;
		} else {
			RETVAL = NULL;
			g_free(message);
		}
	OUTPUT:
		RETVAL

FILE *
purple_mkstemp(OUTLIST gchar_own *path, binary)
	gboolean binary
	PROTOTYPE: $

const char *
purple_normalize(account, str)
	Purple::Account account
	const char *str

gboolean
purple_program_is_valid(program)
	const char *program

gchar_own *
purple_strdup_withhtml(src)
	const gchar *src

gchar_own *
purple_text_strip_mnemonic(in)
	const char *in

time_t
purple_time_build(year, month, day, hour, min, sec)
	int year
	int month
	int day
	int hour
	int min
	int sec

const char *
purple_time_format(tm)
	const struct tm *tm

const char *
purple_unescape_filename(str)
	const char *str

gchar_own *
purple_unescape_html(html)
	const char *html

const char *
purple_url_decode(str)
	const char *str

const char *
purple_url_encode(str)
	const char *str

 # XXX: this made perl assert()...
 #
 #gboolean
 #purple_url_parse(url, OUTLIST gchar_own *ret_host, OUTLIST int ret_port, OUTLIST gchar_own *ret_path, OUTLIST gchar_own *ret_user, OUTLIST gchar_own *ret_passwd)
 #	const char *url
 #	PROTOTYPE: $

void
purple_url_parse(url)
	const char *url
	PREINIT:
		char *ret_host;
		int ret_port;
		char *ret_path;
		char *ret_user;
		char *ret_passwd;
		gboolean ret;
	PPCODE:
		ret = purple_url_parse(url, &ret_host, &ret_port, &ret_path, &ret_user, &ret_passwd);
		XPUSHs(sv_2mortal(newSViv(ret)));
		XPUSHs(ret_host ? sv_2mortal(newSVpv(ret_host, 0)) : sv_2mortal(newSV(0)));
		XPUSHs(sv_2mortal(newSViv(ret_port)));
		XPUSHs(ret_path ? sv_2mortal(newSVpv(ret_path, 0)) : sv_2mortal(newSV(0)));
		XPUSHs(ret_user ? sv_2mortal(newSVpv(ret_user, 0)) : sv_2mortal(newSV(0)));
		XPUSHs(ret_passwd ? sv_2mortal(newSVpv(ret_passwd, 0)) : sv_2mortal(newSV(0)));
		g_free(ret_host);
		g_free(ret_path);
		g_free(ret_user);
		g_free(ret_passwd);


const char *
purple_user_dir()

const char *
purple_utf8_strftime(const char *format, const struct tm *tm);

gboolean
purple_utf8_has_word(haystack, needle)
	const char* haystack
	const char* needle

gchar_own*
purple_utf8_ncr_decode(in)
	const char* in

gchar_own*
purple_utf8_ncr_encode(in)
	const char* in

gchar_own*
purple_utf8_salvage(str)
	const char* str

int
purple_utf8_strcasecmp(a, b)
	const char* a
	const char* b

gchar_own*
purple_utf8_try_convert(str)
	const char* str

gboolean
purple_ip_address_is_valid(ip)
	const char* ip

const char*
purple_normalize_nocase(account, str)
	Purple::Account account
	const char* str

const gchar*
purple_gai_strerror(errnum)
	gint errnum

void
purple_got_protocol_handler_uri(uri)
	const char* uri

gchar_own*
purple_base16_encode(const guchar *data, gsize length(data))
	PROTOTYPE: $

gchar_own*
purple_base16_encode_chunked(const guchar *data, gsize length(data))
	PROTOTYPE: $

gchar_own*
purple_base64_encode(const guchar *data, gsize length(data))
	PROTOTYPE: $

void
purple_restore_default_signal_handlers()

SV *
purple_base16_decode(str)
	const char* str
	PREINIT:
	gsize len;
	guchar *ret;
	CODE:
		ret = purple_base16_decode(str, &len);
		if(ret && len > 0) {
			RETVAL = newSVpv((gchar *)ret, len);
		} else {
			g_free(ret);
			XSRETURN_UNDEF;
		}
		g_free(ret);
	OUTPUT:
		RETVAL

SV*
purple_base64_decode(str)
	const char* str
	PREINIT:
	gsize len;
	guchar *ret;
	CODE:
		ret = purple_base64_decode(str, &len);
		if(ret && len > 0) {
			RETVAL = newSVpv((gchar *)ret, len);
		} else {
			g_free(ret);
			XSRETURN_UNDEF;
		}
		g_free(ret);
	OUTPUT:
		RETVAL

SV*
purple_quotedp_decode(str)
	const char* str
	PREINIT:
	gsize len;
	guchar *ret;
	CODE:
		ret = purple_quotedp_decode(str, &len);
		if(len) {
			RETVAL = newSVpv((gchar *)ret, len);
		} else {
			g_free(ret);
			XSRETURN_UNDEF;
		}
		g_free(ret);
	OUTPUT:
		RETVAL

void
purple_uri_list_extract_uris(uri_list)
	const gchar* uri_list
	PREINIT:
		GList *l = NULL, *gl = NULL;
	PPCODE:
		gl = purple_uri_list_extract_uris(uri_list);
		for(l = gl; l; l = l->next) {
			XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
			g_free(l->data);
		}
		g_list_free(gl);

void
purple_uri_list_extract_filenames(uri_list)
	const gchar* uri_list
	PREINIT:
		GList *l = NULL, *gl = NULL;
	PPCODE:
		gl = purple_uri_list_extract_filenames(uri_list);
		for(l = gl; l; l = l->next) {
			XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
			g_free(l->data);
		}
		g_list_free(gl);

MODULE = Purple::Util  PACKAGE = Purple::Util::Str  PREFIX = purple_str_
PROTOTYPES: ENABLE

gchar_own *
purple_str_add_cr(str)
	const char *str

gchar_own *
purple_str_binary_to_ascii(const unsigned char *binary, guint length(binary))
	PROTOTYPE: $

gboolean
purple_str_has_prefix(s, p)
	const char *s
	const char *p

gboolean
purple_str_has_suffix(s, x)
	const char *s
	const char *x

gchar_own *
purple_str_seconds_to_string(sec)
	guint sec

gchar_own *
purple_str_size_to_units(size)
	size_t size

time_t
purple_str_to_time(timestamp, utc = FALSE, tm = NULL, OUTLIST long tz_off, OUTLIST const char *rest)
	const char *timestamp
	gboolean utc
	struct tm *tm
	PROTOTYPE: $;$$

MODULE = Purple::Util  PACKAGE = Purple::Util::Date  PREFIX = purple_date_
PROTOTYPES: ENABLE

const char *
purple_date_format_full(tm)
	const struct tm *tm

const char *
purple_date_format_long(tm)
	const struct tm *tm

const char *
purple_date_format_short(tm)
	const struct tm *tm

MODULE = Purple::Util  PACKAGE = Purple::Util::Markup  PREFIX = purple_markup_
PROTOTYPES: ENABLE

gboolean
purple_markup_extract_info_field(str, len, user_info, start_token, skip, end_token, check_value, no_value_token, display_name, is_link, link_prefix, format_cb)
	const char *str
	int len
	Purple::NotifyUserInfo user_info
	const char *start_token
	int skip
	const char *end_token
	char check_value
	const char *no_value_token
	const char *display_name
	gboolean is_link
	const char *link_prefix
	Purple::Util::InfoFieldFormatCallback format_cb

 # XXX: returning start/end to perl doesn't make a lot of sense...
 # XXX: the actual tag data can be gotten with $start =~ s/$end//g;
void
purple_markup_find_tag(needle, haystack)
	const char *needle
	const char *haystack
	PREINIT:
		const char *start = NULL;
		const char *end = NULL;
		GData *attributes;
		gboolean ret;
		HV *hv = NULL;
	PPCODE:
		ret = purple_markup_find_tag(needle, haystack, &start, &end, &attributes);
		if(!ret) XSRETURN_UNDEF;

		hv = newHV();
		g_datalist_foreach(&attributes, (GDataForeachFunc) markup_find_tag_foreach, hv);
		g_datalist_clear(&attributes);

		XPUSHs(sv_2mortal(newSVpv(start, 0)));
		XPUSHs(sv_2mortal(newSVpv(end, 0)));
		XPUSHs(sv_2mortal(newRV_noinc((SV *) hv)));

gchar_own *
purple_markup_get_tag_name(tag)
	const char *tag

void
purple_markup_html_to_xhtml(html, OUTLIST gchar_own *dest_xhtml, OUTLIST gchar_own *dest_plain)
	const char *html
	PROTOTYPE: $

gchar_own *
purple_markup_linkify(str)
	const char *str

gchar_own *
purple_markup_slice(str, x, y)
	const char *str
	guint x
	guint y

gchar_own *
purple_markup_strip_html(str)
	const char *str

gchar_own *
purple_markup_get_css_property(style, opt)
	const gchar* style
	const gchar* opt

SV*
purple_markup_unescape_entity(text)
	const char* text
	PREINIT:
	int length;
	CODE:
		{
			const char *str = purple_markup_unescape_entity(text, &length);
			if(length) {
				RETVAL = newSVpv(str, length);
			} else {
				XSRETURN_UNDEF;
			}
		}
	OUTPUT:
		RETVAL


MODULE = Purple::Util  PACKAGE = Purple::Util  PREFIX = purple_util_
PROTOTYPES: ENABLE

 #XXX: expand...
void
purple_util_fetch_url(plugin, url, full, user_agent, http11, cb)
	Purple::Plugin plugin
	const char *url
	gboolean full
	const char *user_agent
	gboolean http11
	SV * cb
PREINIT:
	PurpleUtilFetchUrlData *data;
PPCODE:
	/* XXX: i don't like this... only plugins can use it... */
	SV *sv = purple_perl_sv_from_fun(plugin, cb);

	if (sv != NULL) {
		data = purple_util_fetch_url(url, full, user_agent, http11,
		                      purple_perl_util_url_cb, sv);
		XPUSHs(sv_2mortal(purple_perl_bless_object(data, "Purple::Util::FetchUrlData")));
	} else {
		purple_debug_warning("perl", "Callback not a valid type, only strings and coderefs allowed in purple_util_fetch_url.\n");
		XSRETURN_UNDEF;
	}

void
purple_util_set_user_dir(dir)
	const char *dir

gboolean
purple_util_write_data_to_file(filename, const char *data, size_t length(data))
	const char *filename
	PROTOTYPE: $$

void
purple_util_set_current_song(title, artist, album)
	const char *title
	const char *artist
	const char *album

gchar_own*
purple_util_format_song_info(title, artist, album, unused)
	const char* title
	const char* artist
	const char* album
	gpointer unused

const char*
purple_util_get_image_extension(const char *data, size_t length(data))
	PROTOTYPE: $

gchar_own*
purple_util_get_image_filename(const char *image_data, size_t length(image_data))
	PROTOTYPE: $

Purple::XMLNode
purple_util_read_xml_from_file(filename, description)
	const char* filename
	const char* description

gboolean
purple_util_write_data_to_file_absolute(filename_full, char *data, gssize length(data))
	const char* filename_full
	PROTOTYPE: $$

