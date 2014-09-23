#include "module.h"

MODULE = Purple::Cipher  PACKAGE = Purple::Cipher  PREFIX = purple_cipher_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::Cipher::BatchMode", 1);
	HV *cipher_caps = gv_stashpv("Purple::Cipher::Caps", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_CIPHER_BATCH_MODE_##name}
		const_iv(ECB),
		const_iv(CBC),
#undef const_iv
	};

	static const constiv bm_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_CIPHER_CAPS_##name}
		const_iv(SET_OPT),
		const_iv(GET_OPT),
		const_iv(INIT),
		const_iv(RESET),
		const_iv(UNINIT),
		const_iv(SET_IV),
		const_iv(APPEND),
		const_iv(DIGEST),
		const_iv(ENCRYPT),
		const_iv(DECRYPT),
		const_iv(SET_SALT),
		const_iv(GET_SALT_SIZE),
		const_iv(SET_KEY),
		const_iv(GET_KEY_SIZE),
		const_iv(SET_BATCH_MODE),
		const_iv(GET_BATCH_MODE),
		const_iv(GET_BLOCK_SIZE),
		const_iv(SET_KEY_WITH_LEN),
		const_iv(UNKNOWN),
#undef const_iv
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = bm_const_iv + sizeof(bm_const_iv) / sizeof(bm_const_iv[0]); civ-- > bm_const_iv; )
		newCONSTSUB(cipher_caps, (char *)civ->name, newSViv(civ->iv));
}

const gchar *
purple_cipher_get_name(cipher)
	Purple::Cipher cipher

guint
purple_cipher_get_capabilities(cipher)
	Purple::Cipher cipher

size_t
purple_cipher_digest_region(name, data_sv, in_len, digest)
	const gchar *name
	SV *data_sv
	size_t in_len
	SV *digest
	PREINIT:
		gboolean ret;
		guchar *buff = NULL;
		guchar *data = NULL;
		size_t data_len;
	CODE:
		data = (guchar *)SvPV(data_sv, data_len);
		SvUPGRADE(digest, SVt_PV);
		buff = (guchar *)SvGROW(digest, in_len);
		ret = purple_cipher_digest_region(name, data, data_len, in_len, buff, &RETVAL);
		if(!ret) {
			SvSetSV_nosteal(digest, &PL_sv_undef);
			XSRETURN_UNDEF;
		}
		SvCUR_set(digest, RETVAL);
		SvPOK_only(digest);
	OUTPUT:
		RETVAL

gchar_own*
purple_cipher_http_digest_calculate_response(algorithm, method, digest_uri, qop, entity, nonce, nonce_count, client_nonce, session_key)
	const gchar* algorithm
	const gchar* method
	const gchar* digest_uri
	const gchar* qop
	const gchar* entity
	const gchar* nonce
	const gchar* nonce_count
	const gchar* client_nonce
	const gchar* session_key

gchar_own*
purple_cipher_http_digest_calculate_session_key(algorithm, username, realm, password, nonce, client_nonce)
	const gchar* algorithm
	const gchar* username
	const gchar* realm
	const gchar* password
	const gchar* nonce
	const gchar* client_nonce

MODULE = Purple::Cipher  PACKAGE = Purple::Ciphers  PREFIX = purple_ciphers_
PROTOTYPES: ENABLE

Purple::Cipher
purple_ciphers_find_cipher(name)
	gchar * name

Purple::Cipher
purple_ciphers_register_cipher(name, ops)
	gchar * name
	Purple::Cipher::Ops ops

gboolean
purple_ciphers_unregister_cipher(cipher)
	Purple::Cipher cipher

void
purple_ciphers_get_ciphers()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_ciphers_get_ciphers(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Cipher")));
	}

Purple::Handle
purple_ciphers_get_handle()

MODULE = Purple::Cipher  PACKAGE = Purple::Cipher::Context  PREFIX = purple_cipher_context_
PROTOTYPES: ENABLE

void
purple_cipher_context_set_option(context, name, value)
	Purple::Cipher::Context context
	gchar *name
	gpointer value

gpointer
purple_cipher_context_get_option(context, name)
	Purple::Cipher::Context context
	gchar *name

Purple::Cipher::Context
purple_cipher_context_new(klass, cipher, extra = NULL)
	Purple::Cipher cipher
	void *extra
	C_ARGS: cipher, extra

Purple::Cipher::Context
purple_cipher_context_new_by_name(klass, name, extra = NULL)
	gchar *name
	void *extra
	C_ARGS: name, extra

void
purple_cipher_context_reset(context, extra = NULL)
	Purple::Cipher::Context context
	gpointer extra

void
purple_cipher_context_destroy(context)
	Purple::Cipher::Context context

void
purple_cipher_context_set_iv(Purple::Cipher::Context context, guchar *iv, size_t length(iv))
	PROTOTYPE: $$

void
purple_cipher_context_append(Purple::Cipher::Context context, guchar *data, size_t length(data))
	PROTOTYPE: $$

size_t
purple_cipher_context_digest(context, in_len, digest)
	Purple::Cipher::Context context
	size_t in_len
	SV *digest
	PREINIT:
		gboolean ret;
		guchar *buff = NULL;
	CODE:
		SvUPGRADE(digest, SVt_PV);
		buff = (guchar *)SvGROW(digest, in_len);
		ret = purple_cipher_context_digest(context, in_len, buff, &RETVAL);
		if(!ret) {
			SvSetSV_nosteal(digest, &PL_sv_undef);
			XSRETURN_UNDEF;
		}
		SvCUR_set(digest, RETVAL);
		SvPOK_only(digest);
	OUTPUT:
		RETVAL

size_t
purple_cipher_context_digest_to_str(context, in_len, digest_s)
	Purple::Cipher::Context context
	size_t in_len
	SV *digest_s
	PREINIT:
		gboolean ret;
		gchar *buff = NULL;
	CODE:
		in_len += 1; /* perl shouldn't need to care about '\0' at the end */
		SvUPGRADE(digest_s, SVt_PV);
		buff = SvGROW(digest_s, in_len);
		ret = purple_cipher_context_digest_to_str(context, in_len, buff, &RETVAL);
		if(!ret) {
			SvSetSV_nosteal(digest_s, &PL_sv_undef);
			XSRETURN_UNDEF;
		}
		SvCUR_set(digest_s, RETVAL);
		SvPOK_only(digest_s);
	OUTPUT:
		RETVAL

gint
purple_cipher_context_encrypt(context, data_sv, output, OUTLIST size_t outlen)
	Purple::Cipher::Context context
	SV *data_sv
	SV *output
	PROTOTYPE: $$$
	PREINIT:
		size_t datalen;
		guchar *buff = NULL;
		guchar *data = NULL;
	CODE:
		data = (guchar *)SvPV(data_sv, datalen);
		SvUPGRADE(output, SVt_PV);
		buff = (guchar *)SvGROW(output, datalen);
		RETVAL = purple_cipher_context_encrypt(context, data, datalen, buff, &outlen);
		if(outlen != 0) {
			SvPOK_only(output);
			SvCUR_set(output, outlen);
		} else {
			SvSetSV_nosteal(output, &PL_sv_undef);
		}
	OUTPUT:
		RETVAL

gint
purple_cipher_context_decrypt(context, data_sv, output, OUTLIST size_t outlen)
	Purple::Cipher::Context context
	SV *data_sv
	SV *output
	PROTOTYPE: $$$
	PREINIT:
		size_t datalen;
		guchar *buff = NULL;
		guchar *data = NULL;
	CODE:
		data = (guchar *)SvPV(data_sv, datalen);
		SvUPGRADE(output, SVt_PV);
		buff = (guchar *)SvGROW(output, datalen);
		RETVAL = purple_cipher_context_decrypt(context, data, datalen, buff, &outlen);
		if(outlen != 0) {
			SvPOK_only(output);
			SvCUR_set(output, outlen);
		} else {
			SvSetSV_nosteal(output, &PL_sv_undef);
		}
	OUTPUT:
		RETVAL

void
purple_cipher_context_set_salt(context, salt)
	Purple::Cipher::Context context
	guchar *salt

size_t
purple_cipher_context_get_salt_size(context)
	Purple::Cipher::Context context

void
purple_cipher_context_set_key(context, key)
	Purple::Cipher::Context context
	guchar *key

size_t
purple_cipher_context_get_key_size(context)
	Purple::Cipher::Context context

void
purple_cipher_context_set_data(context, data)
	Purple::Cipher::Context context
	gpointer data

gpointer
purple_cipher_context_get_data(context)
	Purple::Cipher::Context context

Purple::Cipher::BatchMode
purple_cipher_context_get_batch_mode(context)
	Purple::Cipher::Context context

size_t
purple_cipher_context_get_block_size(context)
	Purple::Cipher::Context context

void
purple_cipher_context_set_batch_mode(context, mode)
	Purple::Cipher::Context context
	Purple::Cipher::BatchMode mode

void
purple_cipher_context_set_key_with_len(Purple::Cipher::Context context, guchar *key, size_t length(key))
	PROTOTYPE: $$

