#include "module.h"

struct cb_data {
	SV *cb;
	SV *user_data;
};

static void cb_cert_verify(PurpleCertificateVerificationStatus st, struct cb_data *d) {
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);

	XPUSHs(sv_2mortal(newSViv(st)));
	XPUSHs(d->user_data);

	PUTBACK;

	call_sv(d->cb, G_VOID | G_EVAL);

	if(SvTRUE(ERRSV)) {
		STRLEN l_a;
		purple_debug_warning("perl", "Failed to run 'certificate verify' callback: %s\n", SvPV(ERRSV, l_a));
	}

	FREETMPS;
	LEAVE;

	SvREFCNT_dec(d->cb);
	SvREFCNT_dec(d->user_data);

	g_free(d);
}

MODULE = Purple::Certificate  PACKAGE = Purple::Certificate  PREFIX = purple_certificate_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::Certificate", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_CERTIFICATE_##name}
		const_iv(INVALID),
		const_iv(VALID),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_certificate_add_ca_search_path(path)
	const char* path

gboolean
purple_certificate_check_subject_name(crt, name)
	Purple::Certificate crt
	const gchar* name

Purple::Certificate
purple_certificate_copy(crt)
	Purple::Certificate crt

void
purple_certificate_destroy(crt)
	Purple::Certificate crt

void
purple_certificate_display_x509(crt)
	Purple::Certificate crt

## changed order of arguments, so that $cert->export($file) could be used
gboolean
purple_certificate_export(crt, filename)
	const gchar* filename
	Purple::Certificate crt
	C_ARGS:
		filename, crt

Purple::Certificate::Pool
purple_certificate_find_pool(scheme_name, pool_name)
	const gchar* scheme_name
	const gchar* pool_name

Purple::Certificate::Scheme
purple_certificate_find_scheme(name)
	const gchar* name

Purple::Certificate::Verifier
purple_certificate_find_verifier(scheme_name, ver_name)
	const gchar* scheme_name
	const gchar* ver_name

Purple::Handle
purple_certificate_get_handle()

gchar_own*
purple_certificate_get_issuer_unique_id(crt)
	Purple::Certificate crt

gchar_own*
purple_certificate_get_subject_name(crt)
	Purple::Certificate crt

gchar_own*
purple_certificate_get_unique_id(crt)
	Purple::Certificate crt

Purple::Certificate
purple_certificate_import(scheme, filename)
	Purple::Certificate::Scheme scheme
	const gchar* filename

gboolean
purple_certificate_register_pool(pool)
	Purple::Certificate::Pool pool

gboolean
purple_certificate_register_scheme(scheme)
	Purple::Certificate::Scheme scheme

gboolean
purple_certificate_register_verifier(vr)
	Purple::Certificate::Verifier vr

gboolean
purple_certificate_signed_by(crt, issuer)
	Purple::Certificate crt
	Purple::Certificate issuer

gboolean
purple_certificate_unregister_pool(pool)
	Purple::Certificate::Pool pool

gboolean
purple_certificate_unregister_scheme(scheme)
	Purple::Certificate::Scheme scheme

gboolean
purple_certificate_unregister_verifier(vr)
	Purple::Certificate::Verifier vr

void
purple_certificate_verify_complete(vrq, st)
	Purple::Certificate::VerificationRequest vrq
	Purple::Certificate::VerificationStatus st

gboolean
purple_certificate_get_times(crt, OUTLIST time_t activation, OUTLIST time_t expiration)
	Purple::Certificate crt
	PROTOTYPE: $

void
purple_certificate_destroy_list(...)
	PREINIT:
	GList* l = NULL;
	int i = 0;
	CODE:
		for(i = 0; i < items; i++) { /* PurpleCertificate */
			l = g_list_prepend(l, purple_perl_ref_object(ST(i)));
		}
		purple_certificate_destroy_list(l);

void
purple_certificate_get_pools()
	PREINIT:
		GList *l;
	PPCODE:
		for(l = purple_certificate_get_pools(); l; l = l->next) {
			XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Certificate::Pool")));
		}

void
purple_certificate_get_schemes()
	PREINIT:
		GList *l;
	PPCODE:
		for(l = purple_certificate_get_schemes(); l; l = l->next) {
			XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Certificate::Scheme")));
		}

void
purple_certificate_get_verifiers()
	PREINIT:
		GList *l;
	PPCODE:
		for(l = purple_certificate_get_verifiers(); l; l = l->next) {
			XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Certificate::Verifier")));
		}

void
purple_certificate_check_signature_chain(...)
	PREINIT:
		GList *l = NULL;
		gboolean ret;
		int i;
	PPCODE:
		for(i = 0; i < items; i++) { /* PurpleCertificate */
			l = g_list_prepend(l, purple_perl_ref_object(ST(i)));
		}
		l = g_list_reverse(l);
		ret = purple_certificate_check_signature_chain(l);
		g_list_free(l);
		if(ret) XSRETURN_YES;
		XSRETURN_NO;

SV*
purple_certificate_get_fingerprint_sha1(crt)
	Purple::Certificate crt
	PREINIT:
		GByteArray *gba = NULL;
	CODE:
		gba = purple_certificate_get_fingerprint_sha1(crt);
		RETVAL = newSVpv((gchar *)gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
	OUTPUT:
		RETVAL

void
purple_certificate_verify(verifier, subject_name, cert_chain, cb, cb_data)
	Purple::Certificate::Verifier verifier
	const gchar* subject_name
	AV* cert_chain
	CV *cb
	SV *cb_data
	PREINIT:
		GList *l = NULL;
		int len = 0, i = 0;
		struct cb_data *d = NULL;
	PPCODE:
		len = av_len(cert_chain);
		for(i = 0; i <= len; i++) {
			SV **sv = av_fetch(cert_chain, i, 0);
			if(!sv || !purple_perl_is_ref_object(*sv)) {
				g_list_free(l);
				warn("Purple::Certificate::verify: cert_chain: non-purple object in array...");
				XSRETURN_UNDEF;
			}
			l = g_list_prepend(l, purple_perl_ref_object(*sv));
		}
		l = g_list_reverse(l);

		d = g_new0(struct cb_data, 1);
		d->cb = newSVsv(ST(3));
		d->user_data = newSVsv(cb_data);
		
		purple_certificate_verify(verifier, subject_name, l, (PurpleCertificateVerifiedCallback) cb_cert_verify, d);

		g_list_free(l);

MODULE = Purple::Certificate  PACKAGE = Purple::Certificate::Pool  PREFIX = purple_certificate_pool_
PROTOTYPES: ENABLE

void
purple_certificate_pool_get_idlist(pool)
	Purple::Certificate::Pool pool
	PREINIT:
		GList *l, *b;
	PPCODE:
		b = purple_certificate_pool_get_idlist(pool);
		for(l = b; l; l = l->next) {
			XPUSHs(sv_2mortal(newSVpv(l->data, 0)));
		}
		purple_certificate_pool_destroy_idlist(b);

gboolean
purple_certificate_pool_contains(pool, id)
	Purple::Certificate::Pool pool
	const gchar* id

gboolean
purple_certificate_pool_delete(pool, id)
	Purple::Certificate::Pool pool
	const gchar* id

Purple::Certificate::Scheme
purple_certificate_pool_get_scheme(pool)
	Purple::Certificate::Pool pool

gchar_own*
purple_certificate_pool_mkpath(pool, id)
	Purple::Certificate::Pool pool
	const gchar* id

Purple::Certificate
purple_certificate_pool_retrieve(pool, id)
	Purple::Certificate::Pool pool
	const gchar* id

gboolean
purple_certificate_pool_store(pool, id, crt)
	Purple::Certificate::Pool pool
	const gchar* id
	Purple::Certificate crt

gboolean
purple_certificate_pool_usable(pool)
	Purple::Certificate::Pool pool

