/**
 * @file certificate.c Public-Key Certificate API
 * @ingroup core
 */

/*
 *
 * purple
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
#include "certificate.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "request.h"
#include "signals.h"
#include "util.h"

/** List holding pointers to all registered certificate schemes */
static GList *cert_schemes = NULL;
/** List of registered Verifiers */
static GList *cert_verifiers = NULL;
/** List of registered Pools */
static GList *cert_pools = NULL;

/*
 * TODO: Merge this with PurpleCertificateVerificationStatus for 3.0.0 */
typedef enum {
	PURPLE_CERTIFICATE_UNKNOWN_ERROR = -1,

	/* Not an error */
	PURPLE_CERTIFICATE_NO_PROBLEMS = 0,

	/* Non-fatal */
	PURPLE_CERTIFICATE_NON_FATALS_MASK = 0x0000FFFF,

	/* The certificate is self-signed. */
	PURPLE_CERTIFICATE_SELF_SIGNED = 0x01,

	/* The CA is not in libpurple's pool of certificates. */
	PURPLE_CERTIFICATE_CA_UNKNOWN = 0x02,

	/* The current time is before the certificate's specified
	 * activation time.
	 */
	PURPLE_CERTIFICATE_NOT_ACTIVATED = 0x04,

	/* The current time is after the certificate's specified expiration time */
	PURPLE_CERTIFICATE_EXPIRED = 0x08,

	/* The certificate's subject name doesn't match the expected */
	PURPLE_CERTIFICATE_NAME_MISMATCH = 0x10,

	/* No CA pool was found. This shouldn't happen... */
	PURPLE_CERTIFICATE_NO_CA_POOL = 0x20,

	/* Fatal */
	PURPLE_CERTIFICATE_FATALS_MASK = 0xFFFF0000,

	/* The signature chain could not be validated. Due to limitations in the
	 * the current API, this also indicates one of the CA certificates in the
	 * chain is expired (or not yet activated). FIXME 3.0.0 */
	PURPLE_CERTIFICATE_INVALID_CHAIN = 0x10000,

	/* The signature has been revoked. */
	PURPLE_CERTIFICATE_REVOKED = 0x20000,

	PURPLE_CERTIFICATE_LAST = 0x40000,
} PurpleCertificateInvalidityFlags;

static const gchar *
invalidity_reason_to_string(PurpleCertificateInvalidityFlags flag)
{
	switch (flag) {
		case PURPLE_CERTIFICATE_SELF_SIGNED:
			return _("The certificate is self-signed and cannot be "
			         "automatically checked.");
			break;
		case PURPLE_CERTIFICATE_CA_UNKNOWN:
			return _("The certificate is not trusted because no certificate "
			         "that can verify it is currently trusted.");
			break;
		case PURPLE_CERTIFICATE_NOT_ACTIVATED:
			return _("The certificate is not valid yet.  Check that your "
			         "computer's date and time are accurate.");
			break;
		case PURPLE_CERTIFICATE_EXPIRED:
			return _("The certificate has expired and should not be "
			         "considered valid.  Check that your computer's date "
			         "and time are accurate.");
			break;
		case PURPLE_CERTIFICATE_NAME_MISMATCH:
			/* Translators: "domain" refers to a DNS domain (e.g. talk.google.com) */
			return _("The certificate presented is not issued to this domain.");
			break;
		case PURPLE_CERTIFICATE_NO_CA_POOL:
			return _("You have no database of root certificates, so "
			         "this certificate cannot be validated.");
			break;
		case PURPLE_CERTIFICATE_INVALID_CHAIN:
			return _("The certificate chain presented is invalid.");
			break;
		case PURPLE_CERTIFICATE_REVOKED:
			return _("The certificate has been revoked.");
			break;
		case PURPLE_CERTIFICATE_UNKNOWN_ERROR:
		default:
			return _("An unknown certificate error occurred.");
			break;
	}
}

void
purple_certificate_verify (PurpleCertificateVerifier *verifier,
			   const gchar *subject_name, GList *cert_chain,
			   PurpleCertificateVerifiedCallback cb,
			   gpointer cb_data)
{
	PurpleCertificateVerificationRequest *vrq;
	PurpleCertificateScheme *scheme;

	g_return_if_fail(subject_name != NULL);
	/* If you don't have a cert to check, why are you requesting that it
	   be verified? */
	g_return_if_fail(cert_chain != NULL);
	g_return_if_fail(cb != NULL);

	/* Look up the CertificateScheme */
	scheme = purple_certificate_find_scheme(verifier->scheme_name);
	g_return_if_fail(scheme);

	/* Check that at least the first cert in the chain matches the
	   Verifier scheme */
	g_return_if_fail(scheme ==
			 ((PurpleCertificate *) (cert_chain->data))->scheme);

	/* Construct and fill in the request fields */
	vrq = g_new0(PurpleCertificateVerificationRequest, 1);
	vrq->verifier = verifier;
	vrq->scheme = scheme;
	vrq->subject_name = g_strdup(subject_name);
	vrq->cert_chain = purple_certificate_copy_list(cert_chain);
	vrq->cb = cb;
	vrq->cb_data = cb_data;

	/* Initiate verification */
	(verifier->start_verification)(vrq);
}

void
purple_certificate_verify_complete(PurpleCertificateVerificationRequest *vrq,
				   PurpleCertificateVerificationStatus st)
{
	PurpleCertificateVerifier *vr;

	g_return_if_fail(vrq);

	if (st == PURPLE_CERTIFICATE_VALID) {
		purple_debug_info("certificate",
				  "Successfully verified certificate for %s\n",
				  vrq->subject_name);
	} else {
		purple_debug_error("certificate",
				  "Failed to verify certificate for %s\n",
				  vrq->subject_name);
	}

	/* Pass the results on to the request's callback */
	(vrq->cb)(st, vrq->cb_data);

	/* And now to eliminate the request */
	/* Fetch the Verifier responsible... */
	vr = vrq->verifier;
	/* ...and order it to KILL */
	(vr->destroy_request)(vrq);

	/* Now the internals have been cleaned up, so clean up the libpurple-
	   created elements */
	g_free(vrq->subject_name);
	purple_certificate_destroy_list(vrq->cert_chain);

	/*  A structure born
	 *          to much ado
	 *                   and with so much within.
	 * It reaches now
	 *             its quiet end. */
	g_free(vrq);
}


PurpleCertificate *
purple_certificate_copy(PurpleCertificate *crt)
{
	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme, NULL);
	g_return_val_if_fail(crt->scheme->copy_certificate, NULL);

	return (crt->scheme->copy_certificate)(crt);
}

GList *
purple_certificate_copy_list(GList *crt_list)
{
	GList *new_l, *l;

	/* First, make a shallow copy of the list */
	new_l = g_list_copy(crt_list);

	/* Now go through and actually duplicate each certificate */
	for (l = new_l; l; l = l->next) {
		l->data = purple_certificate_copy(l->data);
	}

	return new_l;
}

void
purple_certificate_destroy (PurpleCertificate *crt)
{
	PurpleCertificateScheme *scheme;

	if (NULL == crt) return;

	scheme = crt->scheme;

	(scheme->destroy_certificate)(crt);
}

void
purple_certificate_destroy_list (GList * crt_list)
{
	PurpleCertificate *crt;
	GList *l;

	for (l=crt_list; l; l = l->next) {
		crt = (PurpleCertificate *) l->data;
		purple_certificate_destroy(crt);
	}

	g_list_free(crt_list);
}

gboolean
purple_certificate_signed_by(PurpleCertificate *crt, PurpleCertificate *issuer)
{
	PurpleCertificateScheme *scheme;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(issuer, FALSE);

	scheme = crt->scheme;
	g_return_val_if_fail(scheme, FALSE);
	/* We can't compare two certs of unrelated schemes, obviously */
	g_return_val_if_fail(issuer->scheme == scheme, FALSE);

	return (scheme->signed_by)(crt, issuer);
}

gboolean
purple_certificate_check_signature_chain_with_failing(GList *chain,
                                                      PurpleCertificate **failing)
{
	GList *cur;
	PurpleCertificate *crt, *issuer;
	gchar *uid;
	time_t now, activation, expiration;
	gboolean ret;

	g_return_val_if_fail(chain, FALSE);

	if (failing)
		*failing = NULL;

	uid = purple_certificate_get_unique_id((PurpleCertificate *) chain->data);
	purple_debug_info("certificate",
			  "Checking signature chain for uid=%s\n",
			  uid);
	g_free(uid);

	/* If this is a single-certificate chain, say that it is valid */
	if (chain->next == NULL) {
		purple_debug_info("certificate",
				  "...Singleton. We'll say it's valid.\n");
		return TRUE;
	}

	now = time(NULL);

	/* Load crt with the first certificate */
	crt = (PurpleCertificate *)(chain->data);
	/* And start with the second certificate in the chain */
	for ( cur = chain->next; cur; cur = cur->next ) {

		issuer = (PurpleCertificate *)(cur->data);

		uid = purple_certificate_get_unique_id(issuer);

		ret = purple_certificate_get_times(issuer, &activation, &expiration);
		if (!ret || now < activation || now > expiration) {
			if (!ret)
				purple_debug_error("certificate",
						"...Failed to get validity times for certificate %s\n"
						"Chain is INVALID\n", uid);
			else if (now > expiration)
				purple_debug_error("certificate",
						"...Issuer %s expired at %s\nChain is INVALID\n",
						uid, ctime(&expiration));
			else
				purple_debug_error("certificate",
						"...Not-yet-activated issuer %s will be valid at %s\n"
						"Chain is INVALID\n", uid, ctime(&activation));

			if (failing)
				*failing = crt;

			g_free(uid);
			return FALSE;
		}

		/* Check the signature for this link */
		if (! purple_certificate_signed_by(crt, issuer) ) {
			purple_debug_error("certificate",
					  "...Bad or missing signature by %s\nChain is INVALID\n",
					  uid);
			g_free(uid);

			if (failing)
				*failing = crt;

			return FALSE;
		}

		purple_debug_info("certificate",
				  "...Good signature by %s\n",
				  uid);
		g_free(uid);

		/* The issuer is now the next crt whose signature is to be
		   checked */
		crt = issuer;
	}

	/* If control reaches this point, the chain is valid */
	purple_debug_info("certificate", "Chain is VALID\n");
	return TRUE;
}

gboolean
purple_certificate_check_signature_chain(GList *chain)
{
	return purple_certificate_check_signature_chain_with_failing(chain, NULL);
}

PurpleCertificate *
purple_certificate_import(PurpleCertificateScheme *scheme, const gchar *filename)
{
	g_return_val_if_fail(scheme, NULL);
	g_return_val_if_fail(scheme->import_certificate, NULL);
	g_return_val_if_fail(filename, NULL);

	return (scheme->import_certificate)(filename);
}

GSList *
purple_certificates_import(PurpleCertificateScheme *scheme, const gchar *filename)
{
	g_return_val_if_fail(scheme, NULL);
	g_return_val_if_fail(scheme->import_certificates, NULL);
	g_return_val_if_fail(filename, NULL);

	return (scheme->import_certificates)(filename);
}

gboolean
purple_certificate_export(const gchar *filename, PurpleCertificate *crt)
{
	PurpleCertificateScheme *scheme;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme, FALSE);

	scheme = crt->scheme;
	g_return_val_if_fail(scheme->export_certificate, FALSE);

	return (scheme->export_certificate)(filename, crt);
}

static gboolean
byte_arrays_equal(const GByteArray *array1, const GByteArray *array2)
{
	g_return_val_if_fail(array1 != NULL, FALSE);
	g_return_val_if_fail(array2 != NULL, FALSE);

	return (array1->len == array2->len) &&
		(0 == memcmp(array1->data, array2->data, array1->len));
}

GByteArray *
purple_certificate_get_fingerprint_sha1(PurpleCertificate *crt)
{
	PurpleCertificateScheme *scheme;
	GByteArray *fpr;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme, NULL);

	scheme = crt->scheme;

	g_return_val_if_fail(scheme->get_fingerprint_sha1, NULL);

	fpr = (scheme->get_fingerprint_sha1)(crt);

	return fpr;
}

gchar *
purple_certificate_get_unique_id(PurpleCertificate *crt)
{
	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme, NULL);
	g_return_val_if_fail(crt->scheme->get_unique_id, NULL);

	return (crt->scheme->get_unique_id)(crt);
}

gchar *
purple_certificate_get_issuer_unique_id(PurpleCertificate *crt)
{
	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme, NULL);
	g_return_val_if_fail(crt->scheme->get_issuer_unique_id, NULL);

	return (crt->scheme->get_issuer_unique_id)(crt);
}

gchar *
purple_certificate_get_subject_name(PurpleCertificate *crt)
{
	PurpleCertificateScheme *scheme;
	gchar *subject_name;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme, NULL);

	scheme = crt->scheme;

	g_return_val_if_fail(scheme->get_subject_name, NULL);

	subject_name = (scheme->get_subject_name)(crt);

	return subject_name;
}

gboolean
purple_certificate_check_subject_name(PurpleCertificate *crt, const gchar *name)
{
	PurpleCertificateScheme *scheme;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme, FALSE);
	g_return_val_if_fail(name, FALSE);

	scheme = crt->scheme;

	g_return_val_if_fail(scheme->check_subject_name, FALSE);

	return (scheme->check_subject_name)(crt, name);
}

gboolean
purple_certificate_get_times(PurpleCertificate *crt, time_t *activation, time_t *expiration)
{
	PurpleCertificateScheme *scheme;

	g_return_val_if_fail(crt, FALSE);

	scheme = crt->scheme;

	g_return_val_if_fail(scheme, FALSE);

	/* If both provided references are NULL, what are you doing calling
	   this? */
	g_return_val_if_fail( (activation != NULL) || (expiration != NULL), FALSE);

	/* Throw the request on down to the certscheme */
	return (scheme->get_times)(crt, activation, expiration);
}

gchar *
purple_certificate_pool_mkpath(PurpleCertificatePool *pool, const gchar *id)
{
	gchar *path;
	gchar *esc_scheme_name, *esc_name, *esc_id;

	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->scheme_name, NULL);
	g_return_val_if_fail(pool->name, NULL);

	/* Escape all the elements for filesystem-friendliness */
	esc_scheme_name = g_strdup(purple_escape_filename(pool->scheme_name));
	esc_name = g_strdup(purple_escape_filename(pool->name));
	esc_id = id ? g_strdup(purple_escape_filename(id)) : NULL;

	path = g_build_filename(purple_user_dir(),
				"certificates", /* TODO: constantize this? */
				esc_scheme_name,
				esc_name,
				esc_id,
				NULL);

	g_free(esc_scheme_name);
	g_free(esc_name);
	g_free(esc_id);
	return path;
}

gboolean
purple_certificate_pool_usable(PurpleCertificatePool *pool)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(pool->scheme_name, FALSE);

	/* Check that the pool's scheme is loaded */
	if (purple_certificate_find_scheme(pool->scheme_name) == NULL) {
		return FALSE;
	}

	return TRUE;
}

PurpleCertificateScheme *
purple_certificate_pool_get_scheme(PurpleCertificatePool *pool)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->scheme_name, NULL);

	return purple_certificate_find_scheme(pool->scheme_name);
}

gboolean
purple_certificate_pool_contains(PurpleCertificatePool *pool, const gchar *id)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->cert_in_pool, FALSE);

	return (pool->cert_in_pool)(id);
}

PurpleCertificate *
purple_certificate_pool_retrieve(PurpleCertificatePool *pool, const gchar *id)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(id, NULL);
	g_return_val_if_fail(pool->get_cert, NULL);

	return (pool->get_cert)(id);
}

gboolean
purple_certificate_pool_store(PurpleCertificatePool *pool, const gchar *id, PurpleCertificate *crt)
{
	gboolean ret = FALSE;

	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->put_cert, FALSE);

	/* Whether crt->scheme matches find_scheme(pool->scheme_name) is not
	   relevant... I think... */
	g_return_val_if_fail(
		g_ascii_strcasecmp(pool->scheme_name, crt->scheme->name) == 0,
		FALSE);

	ret = (pool->put_cert)(id, crt);

	/* Signal that the certificate was stored if success*/
	if (ret) {
		purple_signal_emit(pool, "certificate-stored",
				   pool, id);
	}

	return ret;
}

gboolean
purple_certificate_pool_delete(PurpleCertificatePool *pool, const gchar *id)
{
	gboolean ret = FALSE;

	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->delete_cert, FALSE);

	ret = (pool->delete_cert)(id);

	/* Signal that the certificate was deleted if success */
	if (ret) {
		purple_signal_emit(pool, "certificate-deleted",
				   pool, id);
	}

	return ret;
}

GList *
purple_certificate_pool_get_idlist(PurpleCertificatePool *pool)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->get_idlist, NULL);

	return (pool->get_idlist)();
}

void
purple_certificate_pool_destroy_idlist(GList *idlist)
{
	GList *l;

	/* Iterate through and free them strings */
	for ( l = idlist; l; l = l->next ) {
		g_free(l->data);
	}

	g_list_free(idlist);
}


/****************************************************************************/
/* Builtin Verifiers, Pools, etc.                                           */
/****************************************************************************/

static void
x509_singleuse_verify_cb (PurpleCertificateVerificationRequest *vrq, gint id)
{
	g_return_if_fail(vrq);

	purple_debug_info("certificate/x509_singleuse",
			  "VRQ on cert from %s gave %d\n",
			  vrq->subject_name, id);

	/* Signal what happened back to the caller */
	if (1 == id) {
		/* Accepted! */
		purple_certificate_verify_complete(vrq,
						   PURPLE_CERTIFICATE_VALID);
	} else {
		/* Not accepted */
		purple_certificate_verify_complete(vrq,
						   PURPLE_CERTIFICATE_INVALID);

	}
}

static void
x509_singleuse_start_verify (PurpleCertificateVerificationRequest *vrq)
{
	gchar *sha_asc;
	GByteArray *sha_bin;
	gchar *cn;
	const gchar *cn_match;
	gchar *primary, *secondary;
	PurpleCertificate *crt = (PurpleCertificate *) vrq->cert_chain->data;

	/* Pull out the SHA1 checksum */
	sha_bin = purple_certificate_get_fingerprint_sha1(crt);
	/* Now decode it for display */
	sha_asc = purple_base16_encode_chunked(sha_bin->data,
					       sha_bin->len);

	/* Get the cert Common Name */
	cn = purple_certificate_get_subject_name(crt);

	/* Determine whether the name matches */
	if (purple_certificate_check_subject_name(crt, vrq->subject_name)) {
		cn_match = "";
	} else {
		cn_match = _("(DOES NOT MATCH)");
	}

	/* Make messages */
	primary = g_strdup_printf(_("%s has presented the following certificate for just-this-once use:"), vrq->subject_name);
	secondary = g_strdup_printf(_("Common name: %s %s\nFingerprint (SHA1): %s"), cn, cn_match, sha_asc);

	/* Make a semi-pretty display */
	purple_request_accept_cancel(
		vrq->cb_data, /* TODO: Find what the handle ought to be */
		_("Single-use Certificate Verification"),
		primary,
		secondary,
		0,            /* Accept by default */
		NULL,         /* No account */
		NULL,         /* No other user */
		NULL,         /* No associated conversation */
		vrq,
		x509_singleuse_verify_cb,
		x509_singleuse_verify_cb );

	/* Cleanup */
	g_free(cn);
	g_free(primary);
	g_free(secondary);
	g_free(sha_asc);
	g_byte_array_free(sha_bin, TRUE);
}

static void
x509_singleuse_destroy_request (PurpleCertificateVerificationRequest *vrq)
{
	/* I don't do anything! */
}

static PurpleCertificateVerifier x509_singleuse = {
	"x509",                         /* Scheme name */
	"singleuse",                    /* Verifier name */
	x509_singleuse_start_verify,    /* start_verification function */
	x509_singleuse_destroy_request, /* Request cleanup operation */

	NULL,
	NULL,
	NULL,
	NULL
};



/***** X.509 Certificate Authority pool, keyed by Distinguished Name *****/
/* This is implemented in what may be the most inefficient and bugprone way
   possible; however, future optimizations should not be difficult. */

static PurpleCertificatePool x509_ca;

/** Holds a key-value pair for quickish certificate lookup */
typedef struct {
	gchar *dn;
	PurpleCertificate *crt;
} x509_ca_element;

static void
x509_ca_element_free(x509_ca_element *el)
{
	if (NULL == el) return;

	g_free(el->dn);
	purple_certificate_destroy(el->crt);
	g_free(el);
}

/** System directory to probe for CA certificates */
/* This is set in the lazy_init function */
static GList *x509_ca_paths = NULL;

/** A list of loaded CAs, populated from the above path whenever the lazy_init
    happens. Contains pointers to x509_ca_elements */
static GList *x509_ca_certs = NULL;

/** Used for lazy initialization purposes. */
static gboolean x509_ca_initialized = FALSE;

/** Adds a certificate to the in-memory cache, doing nothing else */
static gboolean
x509_ca_quiet_put_cert(PurpleCertificate *crt)
{
	x509_ca_element *el;

	/* lazy_init calls this function, so calling lazy_init here is a
	   Bad Thing */

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme, FALSE);
	/* Make sure that this is some kind of X.509 certificate */
	/* TODO: Perhaps just check crt->scheme->name instead? */
	g_return_val_if_fail(crt->scheme == purple_certificate_find_scheme(x509_ca.scheme_name), FALSE);

	el = g_new0(x509_ca_element, 1);
	el->dn = purple_certificate_get_unique_id(crt);
	el->crt = purple_certificate_copy(crt);
	x509_ca_certs = g_list_prepend(x509_ca_certs, el);

	return TRUE;
}

/* Since the libpurple CertificatePools get registered before plugins are
   loaded, an X.509 Scheme is generally not available when x509_ca_init is
   called, but x509_ca requires X.509 operations in order to properly load.

   To solve this, I present the lazy_init function. It attempts to finish
   initialization of the Pool, but it usually fails when it is called from
   x509_ca_init. However, this is OK; initialization is then simply deferred
   until someone tries to use functions from the pool. */
static gboolean
x509_ca_lazy_init(void)
{
	PurpleCertificateScheme *x509;
	GDir *certdir;
	const gchar *entry;
	GPatternSpec *pempat, *crtpat;
	GList *iter = NULL;
	GSList *crts = NULL;

	if (x509_ca_initialized) return TRUE;

	/* Check that X.509 is registered */
	x509 = purple_certificate_find_scheme(x509_ca.scheme_name);
	if ( !x509 ) {
		purple_debug_warning("certificate/x509/ca",
				  "Lazy init failed because an X.509 Scheme "
				  "is not yet registered. Maybe it will be "
				  "better later.\n");
		return FALSE;
	}

	/* Use a glob to only read .pem files */
	pempat = g_pattern_spec_new("*.pem");
	crtpat = g_pattern_spec_new("*.crt");

	/* Populate the certificates pool from the search path(s) */
	for (iter = x509_ca_paths; iter; iter = iter->next) {
		certdir = g_dir_open(iter->data, 0, NULL);
		if (!certdir) {
			purple_debug_error("certificate/x509/ca", "Couldn't open location '%s'\n", (const char *)iter->data);
			continue;
		}

		while ( (entry = g_dir_read_name(certdir)) ) {
			gchar *fullpath;
			PurpleCertificate *crt;

			if (!g_pattern_match_string(pempat, entry) && !g_pattern_match_string(crtpat, entry)) {
				continue;
			}

			fullpath = g_build_filename(iter->data, entry, NULL);

			/* TODO: Respond to a failure in the following? */
			crts = purple_certificates_import(x509, fullpath);

			while (crts && crts->data) {
				crt = crts->data;
				if (x509_ca_quiet_put_cert(crt)) {
					gchar *name;
					name = purple_certificate_get_subject_name(crt);
					purple_debug_info("certificate/x509/ca",
							  "Loaded %s from %s\n",
							  name ? name : "(unknown)", fullpath);
					g_free(name);
				} else {
					purple_debug_error("certificate/x509/ca",
							  "Failed to load certificate from %s\n",
							  fullpath);
				}
				purple_certificate_destroy(crt);
				crts = g_slist_delete_link(crts, crts);
			}

			g_free(fullpath);
		}
		g_dir_close(certdir);
	}

	g_pattern_spec_free(pempat);
	g_pattern_spec_free(crtpat);

	purple_debug_info("certificate/x509/ca",
			  "Lazy init completed.\n");
	x509_ca_initialized = TRUE;
	return TRUE;
}

static gboolean
x509_ca_init(void)
{
	/* Attempt to point at the appropriate system path */
	if (NULL == x509_ca_paths) {
#ifdef _WIN32
		x509_ca_paths = g_list_append(NULL, g_build_filename(DATADIR,
						   "ca-certs", NULL));
#else
# ifdef SSL_CERTIFICATES_DIR
		x509_ca_paths = g_list_append(NULL, g_strdup(SSL_CERTIFICATES_DIR));
# endif
		x509_ca_paths = g_list_append(x509_ca_paths,
			g_build_filename(DATADIR, "purple", "ca-certs", NULL));
#endif
	}

	/* Attempt to initialize now, but if it doesn't work, that's OK;
	   it will get done later */
	if ( ! x509_ca_lazy_init()) {
		purple_debug_info("certificate/x509/ca",
				  "Init failed, probably because a "
				  "dependency is not yet registered. "
				  "It has been deferred to later.\n");
	}

	return TRUE;
}

static void
x509_ca_uninit(void)
{
	GList *l;

	for (l = x509_ca_certs; l; l = l->next) {
		x509_ca_element *el = l->data;
		x509_ca_element_free(el);
	}
	g_list_free(x509_ca_certs);
	x509_ca_certs = NULL;
	x509_ca_initialized = FALSE;
	g_list_foreach(x509_ca_paths, (GFunc)g_free, NULL);
	g_list_free(x509_ca_paths);
	x509_ca_paths = NULL;
}

/** Look up a ca_element by dn */
static x509_ca_element *
x509_ca_locate_cert(GList *lst, const gchar *dn)
{
	GList *cur;

	for (cur = lst; cur; cur = cur->next) {
		x509_ca_element *el = cur->data;
		if (purple_strequal(dn, el->dn)) {
			return el;
		}
	}
	return NULL;
}

static GSList *
x509_ca_locate_certs(GList *lst, const gchar *dn)
{
	GList *cur;
	GSList *crts = NULL;

	for (cur = lst; cur; cur = cur->next) {
		x509_ca_element *el = cur->data;
		if (purple_strequal(dn, el->dn)) {
			crts = g_slist_prepend(crts, el);
		}
	}
	return crts;
}


static gboolean
x509_ca_cert_in_pool(const gchar *id)
{
	g_return_val_if_fail(x509_ca_lazy_init(), FALSE);
	g_return_val_if_fail(id, FALSE);

	if (x509_ca_locate_cert(x509_ca_certs, id) != NULL) {
		return TRUE;
	} else {
		return FALSE;
	}

	return FALSE;
}

static PurpleCertificate *
x509_ca_get_cert(const gchar *id)
{
	PurpleCertificate *crt = NULL;
	x509_ca_element *el;

	g_return_val_if_fail(x509_ca_lazy_init(), NULL);
	g_return_val_if_fail(id, NULL);

	/* Search the memory-cached pool */
	el = x509_ca_locate_cert(x509_ca_certs, id);

	if (el != NULL) {
		/* Make a copy of the memcached one for the function caller
		   to play with */
		crt = purple_certificate_copy(el->crt);
	} else {
		crt = NULL;
	}

	return crt;
}

static GSList *
x509_ca_get_certs(const gchar *id)
{
	GSList *crts = NULL, *els = NULL;

	g_return_val_if_fail(x509_ca_lazy_init(), NULL);
	g_return_val_if_fail(id, NULL);

	/* Search the memory-cached pool */
	els = x509_ca_locate_certs(x509_ca_certs, id);

	if (els != NULL) {
		GSList *cur;
		/* Make a copy of the memcached ones for the function caller
		   to play with */
		for (cur = els; cur; cur = cur->next) {
			x509_ca_element *el = cur->data;
			crts = g_slist_prepend(crts, purple_certificate_copy(el->crt));
		}
		g_slist_free(els);
	}

	return crts;
}

static gboolean
x509_ca_put_cert(const gchar *id, PurpleCertificate *crt)
{
	gboolean ret = FALSE;

	g_return_val_if_fail(x509_ca_lazy_init(), FALSE);

	/* TODO: This is a quick way of doing this. At some point the change
	   ought to be flushed to disk somehow. */
	ret = x509_ca_quiet_put_cert(crt);

	return ret;
}

static gboolean
x509_ca_delete_cert(const gchar *id)
{
	x509_ca_element *el;

	g_return_val_if_fail(x509_ca_lazy_init(), FALSE);
	g_return_val_if_fail(id, FALSE);

	/* Is the id even in the pool? */
	el = x509_ca_locate_cert(x509_ca_certs, id);
	if ( el == NULL ) {
		purple_debug_warning("certificate/x509/ca",
				     "Id %s wasn't in the pool\n",
				     id);
		return FALSE;
	}

	/* Unlink it from the memory cache and destroy it */
	x509_ca_certs = g_list_remove(x509_ca_certs, el);
	x509_ca_element_free(el);

	return TRUE;
}

static GList *
x509_ca_get_idlist(void)
{
	GList *l, *idlist;

	g_return_val_if_fail(x509_ca_lazy_init(), NULL);

	idlist = NULL;
	for (l = x509_ca_certs; l; l = l->next) {
		x509_ca_element *el = l->data;
		idlist = g_list_prepend(idlist, g_strdup(el->dn));
	}

	return idlist;
}


static PurpleCertificatePool x509_ca = {
	"x509",                       /* Scheme name */
	"ca",                         /* Pool name */
	N_("Certificate Authorities"),/* User-friendly name */
	NULL,                         /* Internal data */
	x509_ca_init,                 /* init */
	x509_ca_uninit,               /* uninit */
	x509_ca_cert_in_pool,         /* Certificate exists? */
	x509_ca_get_cert,             /* Cert retriever */
	x509_ca_put_cert,             /* Cert writer */
	x509_ca_delete_cert,          /* Cert remover */
	x509_ca_get_idlist,           /* idlist retriever */

	NULL,
	NULL,
	NULL,
	NULL

};



/***** Cache of certificates given by TLS/SSL peers *****/
static PurpleCertificatePool x509_tls_peers;

static gboolean
x509_tls_peers_init(void)
{
	gchar *poolpath;
	int ret;

	/* Set up key cache here if it isn't already done */
	poolpath = purple_certificate_pool_mkpath(&x509_tls_peers, NULL);
	ret = purple_build_dir(poolpath, 0700); /* Make it this user only */

	if (ret != 0)
		purple_debug_info("certificate/tls_peers",
				"Could not create %s.  Certificates will not be cached.\n",
				poolpath);

	g_free(poolpath);

	return TRUE;
}

static gboolean
x509_tls_peers_cert_in_pool(const gchar *id)
{
	gchar *keypath;
	gboolean ret = FALSE;

	g_return_val_if_fail(id, FALSE);

	keypath = purple_certificate_pool_mkpath(&x509_tls_peers, id);

	ret = g_file_test(keypath, G_FILE_TEST_IS_REGULAR);

	g_free(keypath);
	return ret;
}

static PurpleCertificate *
x509_tls_peers_get_cert(const gchar *id)
{
	PurpleCertificateScheme *x509;
	PurpleCertificate *crt;
	gchar *keypath;

	g_return_val_if_fail(id, NULL);

	/* Is it in the pool? */
	if ( !x509_tls_peers_cert_in_pool(id) ) {
		return NULL;
	}

	/* Look up the X.509 scheme */
	x509 = purple_certificate_find_scheme("x509");
	g_return_val_if_fail(x509, NULL);

	/* Okay, now find and load that key */
	keypath = purple_certificate_pool_mkpath(&x509_tls_peers, id);
	crt = purple_certificate_import(x509, keypath);

	g_free(keypath);

	return crt;
}

static gboolean
x509_tls_peers_put_cert(const gchar *id, PurpleCertificate *crt)
{
	gboolean ret = FALSE;
	gchar *keypath;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme, FALSE);
	/* Make sure that this is some kind of X.509 certificate */
	/* TODO: Perhaps just check crt->scheme->name instead? */
	g_return_val_if_fail(crt->scheme == purple_certificate_find_scheme(x509_tls_peers.scheme_name), FALSE);

	/* Work out the filename and export */
	keypath = purple_certificate_pool_mkpath(&x509_tls_peers, id);
	ret = purple_certificate_export(keypath, crt);

	g_free(keypath);
	return ret;
}

static gboolean
x509_tls_peers_delete_cert(const gchar *id)
{
	gboolean ret = FALSE;
	gchar *keypath;

	g_return_val_if_fail(id, FALSE);

	/* Is the id even in the pool? */
	if (!x509_tls_peers_cert_in_pool(id)) {
		purple_debug_warning("certificate/tls_peers",
				     "Id %s wasn't in the pool\n",
				     id);
		return FALSE;
	}

	/* OK, so work out the keypath and delete the thing */
	keypath = purple_certificate_pool_mkpath(&x509_tls_peers, id);
	if ( unlink(keypath) != 0 ) {
		purple_debug_error("certificate/tls_peers",
				   "Unlink of %s failed!\n",
				   keypath);
		ret = FALSE;
	} else {
		ret = TRUE;
	}

	g_free(keypath);
	return ret;
}

static GList *
x509_tls_peers_get_idlist(void)
{
	GList *idlist = NULL;
	GDir *dir;
	const gchar *entry;
	gchar *poolpath;

	/* Get a handle on the pool directory */
	poolpath = purple_certificate_pool_mkpath(&x509_tls_peers, NULL);
	dir = g_dir_open(poolpath,
			 0,     /* No flags */
			 NULL); /* Not interested in what the error is */
	g_free(poolpath);

	g_return_val_if_fail(dir, NULL);

	/* Traverse the directory listing and create an idlist */
	while ( (entry = g_dir_read_name(dir)) != NULL ) {
		/* Unescape the filename */
		const char *unescaped = purple_unescape_filename(entry);

		/* Copy the entry name into our list (GLib owns the original
		   string) */
		idlist = g_list_prepend(idlist, g_strdup(unescaped));
	}

	/* Release the directory */
	g_dir_close(dir);

	return idlist;
}

static PurpleCertificatePool x509_tls_peers = {
	"x509",                       /* Scheme name */
	"tls_peers",                  /* Pool name */
	N_("SSL Peers Cache"),        /* User-friendly name */
	NULL,                         /* Internal data */
	x509_tls_peers_init,          /* init */
	NULL,                         /* uninit not required */
	x509_tls_peers_cert_in_pool,  /* Certificate exists? */
	x509_tls_peers_get_cert,      /* Cert retriever */
	x509_tls_peers_put_cert,      /* Cert writer */
	x509_tls_peers_delete_cert,   /* Cert remover */
	x509_tls_peers_get_idlist,    /* idlist retriever */

	NULL,
	NULL,
	NULL,
	NULL
};


/***** A Verifier that uses the tls_peers cache and the CA pool to validate certificates *****/
static PurpleCertificateVerifier x509_tls_cached;


/* The following is several hacks piled together and needs to be fixed.
 * It exists because show_cert (see its comments) needs the original reason
 * given to user_auth in order to rebuild the dialog.
 */
/* TODO: This will cause a ua_ctx to become memleaked if the request(s) get
   closed by handle or otherwise abnormally. */
typedef struct {
	PurpleCertificateVerificationRequest *vrq;
	gchar *reason;
} x509_tls_cached_ua_ctx;

static x509_tls_cached_ua_ctx *
x509_tls_cached_ua_ctx_new(PurpleCertificateVerificationRequest *vrq,
			   const gchar *reason)
{
	x509_tls_cached_ua_ctx *c;

	c = g_new0(x509_tls_cached_ua_ctx, 1);
	c->vrq = vrq;
	c->reason = g_strdup(reason);

	return c;
}


static void
x509_tls_cached_ua_ctx_free(x509_tls_cached_ua_ctx *c)
{
	g_return_if_fail(c);
	g_free(c->reason);
	g_free(c);
}

static void
x509_tls_cached_user_auth(PurpleCertificateVerificationRequest *vrq,
			  const gchar *reason);

static void
x509_tls_cached_show_cert(x509_tls_cached_ua_ctx *c, gint id)
{
	PurpleCertificate *disp_crt = c->vrq->cert_chain->data;

	/* Since clicking a button closes the request, show it again */
	x509_tls_cached_user_auth(c->vrq, c->reason);

	/* Show the certificate AFTER re-opening the dialog so that this
	   appears above the other */
	purple_certificate_display_x509(disp_crt);

	x509_tls_cached_ua_ctx_free(c);
}

static void
x509_tls_cached_user_auth_cb (x509_tls_cached_ua_ctx *c, gint id)
{
	PurpleCertificateVerificationRequest *vrq;
	PurpleCertificatePool *tls_peers;

	g_return_if_fail(c);
	g_return_if_fail(c->vrq);

	vrq = c->vrq;

	x509_tls_cached_ua_ctx_free(c);

	tls_peers = purple_certificate_find_pool("x509","tls_peers");

	if (2 == id) {
		gchar *cache_id = vrq->subject_name;
		purple_debug_info("certificate/x509/tls_cached",
				  "User ACCEPTED cert\nCaching first in chain for future use as %s...\n",
				  cache_id);

		purple_certificate_pool_store(tls_peers, cache_id,
					      vrq->cert_chain->data);

		purple_certificate_verify_complete(vrq,
						   PURPLE_CERTIFICATE_VALID);
	} else {
		purple_debug_warning("certificate/x509/tls_cached",
				  "User REJECTED cert\n");
		purple_certificate_verify_complete(vrq,
						   PURPLE_CERTIFICATE_INVALID);
	}
}

static void
x509_tls_cached_user_auth_accept_cb(x509_tls_cached_ua_ctx *c, gint ignore)
{
	x509_tls_cached_user_auth_cb(c, 2);
}

static void
x509_tls_cached_user_auth_reject_cb(x509_tls_cached_ua_ctx *c, gint ignore)
{
	x509_tls_cached_user_auth_cb(c, 1);
}

/** Validates a certificate by asking the user
 * @param reason    String to explain why the user needs to accept/refuse the
 *                  certificate.
 * @todo Needs a handle argument
 */
static void
x509_tls_cached_user_auth(PurpleCertificateVerificationRequest *vrq,
			  const gchar *reason)
{
	gchar *primary;

	/* Make messages */
	primary = g_strdup_printf(_("Accept certificate for %s?"),
				  vrq->subject_name);

	/* Make a semi-pretty display */
	purple_request_action(
		vrq->cb_data, /* TODO: Find what the handle ought to be */
		_("SSL Certificate Verification"),
		primary,
		reason,
		0,            /* Accept by default */
		NULL,         /* No account */
		NULL,         /* No other user */
		NULL,         /* No associated conversation */
		x509_tls_cached_ua_ctx_new(vrq, reason),
		3,            /* Number of actions */
		_("Accept"), x509_tls_cached_user_auth_accept_cb,
		_("Reject"),  x509_tls_cached_user_auth_reject_cb,
		_("_View Certificate..."), x509_tls_cached_show_cert);

	/* Cleanup */
	g_free(primary);
}

static void
x509_tls_cached_unknown_peer(PurpleCertificateVerificationRequest *vrq,
                             PurpleCertificateInvalidityFlags flags);

static void
x509_tls_cached_complete(PurpleCertificateVerificationRequest *vrq,
                         PurpleCertificateInvalidityFlags flags)
{
	PurpleCertificatePool *tls_peers;
	PurpleCertificate *peer_crt = vrq->cert_chain->data;

	if (flags & PURPLE_CERTIFICATE_FATALS_MASK) {
		/* TODO: Also print any other warnings? */
		const gchar *error;
		gchar *tmp, *secondary;

		if (flags & PURPLE_CERTIFICATE_INVALID_CHAIN)
			error = invalidity_reason_to_string(PURPLE_CERTIFICATE_INVALID_CHAIN);
		else if (flags & PURPLE_CERTIFICATE_REVOKED)
			error = invalidity_reason_to_string(PURPLE_CERTIFICATE_REVOKED);
		else
			error = invalidity_reason_to_string(PURPLE_CERTIFICATE_UNKNOWN_ERROR);

		tmp = g_strdup_printf(_("The certificate for %s could not be validated."),
					vrq->subject_name);
		secondary = g_strconcat(tmp, " ", error, NULL);
		g_free(tmp);

		purple_notify_error(NULL, /* TODO: Probably wrong. */
					_("SSL Certificate Error"),
					_("Unable to validate certificate"),
					secondary);
		g_free(secondary);

		purple_certificate_verify_complete(vrq, PURPLE_CERTIFICATE_INVALID);
		return;
	} else if (flags & PURPLE_CERTIFICATE_NON_FATALS_MASK) {
		/* Non-fatal error. Prompt the user. */
		gchar *tmp;
		GString *errors;
		guint32 i = 1;

		tmp = g_strdup_printf(_("The certificate for %s could not be validated."),
					vrq->subject_name);
		errors = g_string_new(tmp);
		g_free(tmp);

		errors = g_string_append_c(errors, '\n');

		/* Special case a name mismatch because we want to display the two names... */
		if (flags & PURPLE_CERTIFICATE_NAME_MISMATCH) {
			gchar *sn = purple_certificate_get_subject_name(peer_crt);

			if (sn) {
				g_string_append_printf(errors, _("The certificate claims to be "
							"from \"%s\" instead. This could mean that you are "
							"not connecting to the service you believe you are."),
							sn);
				g_free(sn);

				flags &= ~PURPLE_CERTIFICATE_NAME_MISMATCH;
			}
		}

		while (i != PURPLE_CERTIFICATE_LAST) {
			if (flags & i) {
				errors = g_string_append_c(errors, '\n');
				g_string_append(errors, invalidity_reason_to_string(i));
			}

			i <<= 1;
		}

		x509_tls_cached_user_auth(vrq, errors->str);
		g_string_free(errors, TRUE);
		return;
	}

	/* If we reach this point, the certificate is good. */

	/* Look up the local cache and store it there for future use */
	tls_peers = purple_certificate_find_pool(x509_tls_cached.scheme_name,
						 "tls_peers");
	if (tls_peers) {
		if (!purple_certificate_pool_store(tls_peers,vrq->subject_name,
		                                   peer_crt)) {
			purple_debug_error("certificate/x509/tls_cached",
			                   "FAILED to cache peer certificate\n");
		}
	} else {
		purple_debug_error("certificate/x509/tls_cached",
		                   "Unable to locate tls_peers certificate cache.\n");
	}

	purple_certificate_verify_complete(vrq, PURPLE_CERTIFICATE_VALID);
}

static void
x509_tls_cached_cert_in_cache(PurpleCertificateVerificationRequest *vrq,
                              PurpleCertificateInvalidityFlags flags)
{
	/* TODO: Looking this up by name over and over is expensive.
	   Fix, please! */
	PurpleCertificatePool *tls_peers =
		purple_certificate_find_pool(x509_tls_cached.scheme_name,
					     "tls_peers");

	/* The peer's certificate should be the first in the list */
	PurpleCertificate *peer_crt =
		(PurpleCertificate *) vrq->cert_chain->data;

	PurpleCertificate *cached_crt;
	GByteArray *peer_fpr, *cached_fpr;

	/* Load up the cached certificate */
	cached_crt = purple_certificate_pool_retrieve(
		tls_peers, vrq->subject_name);
	if ( !cached_crt ) {
		purple_debug_warning("certificate/x509/tls_cached",
				   "Lookup failed on cached certificate!\n"
				   "Falling back to full verification.\n");
		/* vrq now becomes the problem of unknown_peer */
		x509_tls_cached_unknown_peer(vrq, flags);
		return;
	}

	/* Now get SHA1 sums for both and compare them */
	/* TODO: This is not an elegant way to compare certs */
	peer_fpr = purple_certificate_get_fingerprint_sha1(peer_crt);
	cached_fpr = purple_certificate_get_fingerprint_sha1(cached_crt);
	if (!memcmp(peer_fpr->data, cached_fpr->data, peer_fpr->len)) {
		purple_debug_info("certificate/x509/tls_cached",
				  "Peer cert matched cached\n");
		x509_tls_cached_complete(vrq, flags);
	} else {
		purple_debug_error("certificate/x509/tls_cached",
				  "Peer cert did NOT match cached\n");
		/* vrq now becomes the problem of the user */
		x509_tls_cached_unknown_peer(vrq, flags);
	}

	purple_certificate_destroy(cached_crt);
	g_byte_array_free(peer_fpr, TRUE);
	g_byte_array_free(cached_fpr, TRUE);
}

/*
 * This is called from two points in x509_tls_cached_unknown_peer below
 * once we've verified the signature chain is valid. Now we need to verify
 * the subject name of the certificate.
 */
static void
x509_tls_cached_check_subject_name(PurpleCertificateVerificationRequest *vrq,
                                   PurpleCertificateInvalidityFlags flags)
{
	PurpleCertificate *peer_crt;
	GList *chain = vrq->cert_chain;

	peer_crt = (PurpleCertificate *) chain->data;

	/* Last, check that the hostname matches */
	if ( ! purple_certificate_check_subject_name(peer_crt,
						     vrq->subject_name) ) {
		gchar *sn = purple_certificate_get_subject_name(peer_crt);

		flags |= PURPLE_CERTIFICATE_NAME_MISMATCH;
		purple_debug_error("certificate/x509/tls_cached",
				  "Name mismatch: Certificate given for %s "
				  "has a name of %s\n",
				  vrq->subject_name, sn);
		g_free(sn);
	}

	x509_tls_cached_complete(vrq, flags);
}

/* For when we've never communicated with this party before */
/* TODO: Need ways to specify possibly multiple problems with a cert, or at
   least  reprioritize them.
 */
static void
x509_tls_cached_unknown_peer(PurpleCertificateVerificationRequest *vrq,
                             PurpleCertificateInvalidityFlags flags)
{
	PurpleCertificatePool *ca;
	PurpleCertificate *peer_crt;
	PurpleCertificate *ca_crt, *end_crt;
	PurpleCertificate *failing_crt;
	GList *chain = vrq->cert_chain;
	GSList *ca_crts, *cur;
	GByteArray *last_fpr, *ca_fpr;
	gboolean valid = FALSE;
	gchar *ca_id, *ca2_id;

	peer_crt = (PurpleCertificate *) chain->data;

	/* TODO: Figure out a way to check for a bad signature, as opposed to
	   "not self-signed" */
	if ( purple_certificate_signed_by(peer_crt, peer_crt) ) {
		flags |= PURPLE_CERTIFICATE_SELF_SIGNED;

		purple_debug_info("certificate/x509/tls_cached",
				  "Certificate for %s is self-signed.\n",
				  vrq->subject_name);

		x509_tls_cached_check_subject_name(vrq, flags);
		return;
	} /* if (self signed) */

	ca = purple_certificate_find_pool(x509_tls_cached.scheme_name, "ca");

	/* Next, check that the certificate chain is valid */
	if (!purple_certificate_check_signature_chain_with_failing(chain,
				&failing_crt))
	{
		gboolean chain_validated = FALSE;
		/*
		 * Check if the failing certificate is in the CA store. If it is, then
		 * consider this fully validated. This works around issues with some
		 * prominent intermediate CAs whose signature is md5WithRSAEncryption.
		 * I'm looking at CACert Class 3 here. See #4458 for details.
		 */
		if (ca) {
			gchar *uid = purple_certificate_get_unique_id(failing_crt);
			PurpleCertificate *ca_crt = purple_certificate_pool_retrieve(ca, uid);
			if (ca_crt != NULL) {
				GByteArray *failing_fpr;
				GByteArray *ca_fpr;
				failing_fpr = purple_certificate_get_fingerprint_sha1(failing_crt);
				ca_fpr = purple_certificate_get_fingerprint_sha1(ca_crt);
				if (byte_arrays_equal(failing_fpr, ca_fpr)) {
					purple_debug_info("certificate/x509/tls_cached",
							"Full chain verification failed (probably a bad "
							"signature algorithm), but found the last "
							"certificate %s in the CA pool.\n", uid);
					chain_validated = TRUE;
				}

				g_byte_array_free(failing_fpr, TRUE);
				g_byte_array_free(ca_fpr, TRUE);
			}

			purple_certificate_destroy(ca_crt);
			g_free(uid);
		}

		/*
		 * If we get here, either the cert matched the stuff right above
		 * or it didn't, in which case we give up and complain to the user.
		 */
		if (!chain_validated)
			/* TODO: Tell the user where the chain broke? */
			flags |= PURPLE_CERTIFICATE_INVALID_CHAIN;

		x509_tls_cached_check_subject_name(vrq, flags);
		return;
	} /* if (signature chain not good) */

	/* Next, attempt to verify the last certificate is signed by a trusted
	 * CA, or is a trusted CA (based on fingerprint).
	 */
	/* If, for whatever reason, there is no Certificate Authority pool
	   loaded, we'll verify the subject name and then warn about thsi. */
	if ( !ca ) {
		purple_debug_error("certificate/x509/tls_cached",
				   "No X.509 Certificate Authority pool "
				   "could be found!\n");

		flags |= PURPLE_CERTIFICATE_NO_CA_POOL;

		x509_tls_cached_check_subject_name(vrq, flags);
		return;
	}

	end_crt = g_list_last(chain)->data;

	/* Attempt to look up the last certificate, and the last certificate's
	 * issuer. 
	 */
	ca_id  = purple_certificate_get_issuer_unique_id(end_crt);
	ca2_id = purple_certificate_get_unique_id(end_crt);
	purple_debug_info("certificate/x509/tls_cached",
			  "Checking for a CA with DN=%s\n",
			  ca_id);
	purple_debug_info("certificate/x509/tls_cached",
			  "Also checking for a CA with DN=%s\n",
			  ca2_id);
	ca_crts = g_slist_concat(x509_ca_get_certs(ca_id), x509_ca_get_certs(ca2_id));
	g_free(ca_id);
	g_free(ca2_id);
	if ( NULL == ca_crts ) {
		flags |= PURPLE_CERTIFICATE_CA_UNKNOWN;

		purple_debug_warning("certificate/x509/tls_cached",
				  "No Certificate Authorities with either DN found "
				  "found. I'll prompt the user, I guess.\n");

		x509_tls_cached_check_subject_name(vrq, flags);
		return;
	}

	/*
	 * Check the fingerprints; if they match, then this certificate *is* one
	 * of the designated "trusted roots", and we don't need to verify the
	 * signature. This is good because some of the older roots are self-signed
	 * with bad hash algorithms that we don't want to allow in any other
	 * circumstances (one of Verisign's root CAs is self-signed with MD2).
	 *
	 * If the fingerprints don't match, we'll fall back to checking the
	 * signature.
	 */
	last_fpr = purple_certificate_get_fingerprint_sha1(end_crt);
	for (cur = ca_crts; cur; cur = cur->next) {
		ca_crt = cur->data;
		ca_fpr = purple_certificate_get_fingerprint_sha1(ca_crt);

		if ( byte_arrays_equal(last_fpr, ca_fpr) ||
				purple_certificate_signed_by(end_crt, ca_crt) )
		{
			/* TODO: If signed_by ever returns a reason, maybe mention
			   that, too. */
			/* TODO: Also mention the CA involved. While I could do this
			   now, a full DN is a little much with which to assault the
			   user's poor, leaky eyes. */
			valid = TRUE;
			g_byte_array_free(ca_fpr, TRUE);
			break;
		}

		g_byte_array_free(ca_fpr, TRUE);
	}

	if (valid == FALSE)
		flags |= PURPLE_CERTIFICATE_INVALID_CHAIN;

	g_slist_foreach(ca_crts, (GFunc)purple_certificate_destroy, NULL);
	g_slist_free(ca_crts);
	g_byte_array_free(last_fpr, TRUE);

	x509_tls_cached_check_subject_name(vrq, flags);
}

static void
x509_tls_cached_start_verify(PurpleCertificateVerificationRequest *vrq)
{
	const gchar *tls_peers_name = "tls_peers"; /* Name of local cache */
	PurpleCertificatePool *tls_peers;
	time_t now, activation, expiration;
	PurpleCertificateInvalidityFlags flags = PURPLE_CERTIFICATE_NO_PROBLEMS;
	gboolean ret;

	g_return_if_fail(vrq);

	purple_debug_info("certificate/x509/tls_cached",
			  "Starting verify for %s\n",
			  vrq->subject_name);

	/*
	 * Verify the first certificate (the main one) has been activated and
	 * isn't expired, i.e. activation < now < expiration.
	 */
	now = time(NULL);
	ret = purple_certificate_get_times(vrq->cert_chain->data, &activation,
	                                   &expiration);
	if (!ret) {
		flags |= PURPLE_CERTIFICATE_EXPIRED | PURPLE_CERTIFICATE_NOT_ACTIVATED;
		purple_debug_error("certificate/x509/tls_cached",
				"Failed to get validity times for certificate %s\n",
				vrq->subject_name);
	} else if (now > expiration) {
		flags |= PURPLE_CERTIFICATE_EXPIRED;
		purple_debug_error("certificate/x509/tls_cached",
				"Certificate %s expired at %s\n",
				vrq->subject_name, ctime(&expiration));
	} else if (now < activation) {
		flags |= PURPLE_CERTIFICATE_NOT_ACTIVATED;
		purple_debug_error("certificate/x509/tls_cached",
				"Certificate %s is not yet valid, will be at %s\n",
				vrq->subject_name, ctime(&activation));
	}

	tls_peers = purple_certificate_find_pool(x509_tls_cached.scheme_name,tls_peers_name);

	if (!tls_peers) {
		purple_debug_error("certificate/x509/tls_cached",
				   "Couldn't find local peers cache %s\n",
				   tls_peers_name);

		/* vrq now becomes the problem of unknown_peer */
		x509_tls_cached_unknown_peer(vrq, flags);
		return;
	}

	/* Check if the peer has a certificate cached already */
	purple_debug_info("certificate/x509/tls_cached",
			  "Checking for cached cert...\n");
	if (purple_certificate_pool_contains(tls_peers, vrq->subject_name)) {
		purple_debug_info("certificate/x509/tls_cached",
				  "...Found cached cert\n");
		/* vrq is now the responsibility of cert_in_cache */
		x509_tls_cached_cert_in_cache(vrq, flags);
	} else {
		purple_debug_warning("certificate/x509/tls_cached",
				  "...Not in cache\n");
		/* vrq now becomes the problem of unknown_peer */
		x509_tls_cached_unknown_peer(vrq, flags);
	}
}

static void
x509_tls_cached_destroy_request(PurpleCertificateVerificationRequest *vrq)
{
	g_return_if_fail(vrq);
}

static PurpleCertificateVerifier x509_tls_cached = {
	"x509",                         /* Scheme name */
	"tls_cached",                   /* Verifier name */
	x509_tls_cached_start_verify,   /* Verification begin */
	x509_tls_cached_destroy_request,/* Request cleanup */

	NULL,
	NULL,
	NULL,
	NULL

};

/****************************************************************************/
/* Subsystem                                                                */
/****************************************************************************/
void
purple_certificate_init(void)
{
	/* Register builtins */
	purple_certificate_register_verifier(&x509_singleuse);
	purple_certificate_register_pool(&x509_ca);
	purple_certificate_register_pool(&x509_tls_peers);
	purple_certificate_register_verifier(&x509_tls_cached);
}

void
purple_certificate_uninit(void)
{
	/* Unregister all Verifiers */
	g_list_foreach(cert_verifiers, (GFunc)purple_certificate_unregister_verifier, NULL);

	/* Unregister all Pools */
	g_list_foreach(cert_pools, (GFunc)purple_certificate_unregister_pool, NULL);
}

gpointer
purple_certificate_get_handle(void)
{
	static gint handle;
	return &handle;
}

PurpleCertificateScheme *
purple_certificate_find_scheme(const gchar *name)
{
	PurpleCertificateScheme *scheme = NULL;
	GList *l;

	g_return_val_if_fail(name, NULL);

	/* Traverse the list of registered schemes and locate the
	   one whose name matches */
	for(l = cert_schemes; l; l = l->next) {
		scheme = (PurpleCertificateScheme *)(l->data);

		/* Name matches? that's our man */
		if(!g_ascii_strcasecmp(scheme->name, name))
			return scheme;
	}

	purple_debug_warning("certificate",
			     "CertificateScheme %s requested but not found.\n",
			     name);

	/* TODO: Signalling and such? */

	return NULL;
}

GList *
purple_certificate_get_schemes(void)
{
	return cert_schemes;
}

gboolean
purple_certificate_register_scheme(PurpleCertificateScheme *scheme)
{
	g_return_val_if_fail(scheme != NULL, FALSE);

	/* Make sure no scheme is registered with the same name */
	if (purple_certificate_find_scheme(scheme->name) != NULL) {
		return FALSE;
	}

	/* Okay, we're golden. Register it. */
	cert_schemes = g_list_prepend(cert_schemes, scheme);

	/* TODO: Signalling and such? */

	purple_debug_info("certificate",
			  "CertificateScheme %s registered\n",
			  scheme->name);

	return TRUE;
}

gboolean
purple_certificate_unregister_scheme(PurpleCertificateScheme *scheme)
{
	if (NULL == scheme) {
		purple_debug_warning("certificate",
				     "Attempting to unregister NULL scheme\n");
		return FALSE;
	}

	/* TODO: signalling? */

	/* TODO: unregister all CertificateVerifiers for this scheme?*/
	/* TODO: unregister all CertificatePools for this scheme? */
	/* Neither of the above should be necessary, though */
	cert_schemes = g_list_remove(cert_schemes, scheme);

	purple_debug_info("certificate",
			  "CertificateScheme %s unregistered\n",
			  scheme->name);


	return TRUE;
}

PurpleCertificateVerifier *
purple_certificate_find_verifier(const gchar *scheme_name, const gchar *ver_name)
{
	PurpleCertificateVerifier *vr = NULL;
	GList *l;

	g_return_val_if_fail(scheme_name, NULL);
	g_return_val_if_fail(ver_name, NULL);

	/* Traverse the list of registered verifiers and locate the
	   one whose name matches */
	for(l = cert_verifiers; l; l = l->next) {
		vr = (PurpleCertificateVerifier *)(l->data);

		/* Scheme and name match? */
		if(!g_ascii_strcasecmp(vr->scheme_name, scheme_name) &&
		   !g_ascii_strcasecmp(vr->name, ver_name))
			return vr;
	}

	purple_debug_warning("certificate",
			     "CertificateVerifier %s, %s requested but not found.\n",
			     scheme_name, ver_name);

	/* TODO: Signalling and such? */

	return NULL;
}


GList *
purple_certificate_get_verifiers(void)
{
	return cert_verifiers;
}

gboolean
purple_certificate_register_verifier(PurpleCertificateVerifier *vr)
{
	g_return_val_if_fail(vr != NULL, FALSE);

	/* Make sure no verifier is registered with the same scheme/name */
	if (purple_certificate_find_verifier(vr->scheme_name, vr->name) != NULL) {
		return FALSE;
	}

	/* Okay, we're golden. Register it. */
	cert_verifiers = g_list_prepend(cert_verifiers, vr);

	/* TODO: Signalling and such? */

	purple_debug_info("certificate",
			  "CertificateVerifier %s registered\n",
			  vr->name);
	return TRUE;
}

gboolean
purple_certificate_unregister_verifier(PurpleCertificateVerifier *vr)
{
	if (NULL == vr) {
		purple_debug_warning("certificate",
				     "Attempting to unregister NULL verifier\n");
		return FALSE;
	}

	/* TODO: signalling? */

	cert_verifiers = g_list_remove(cert_verifiers, vr);


	purple_debug_info("certificate",
			  "CertificateVerifier %s unregistered\n",
			  vr->name);

	return TRUE;
}

PurpleCertificatePool *
purple_certificate_find_pool(const gchar *scheme_name, const gchar *pool_name)
{
	PurpleCertificatePool *pool = NULL;
	GList *l;

	g_return_val_if_fail(scheme_name, NULL);
	g_return_val_if_fail(pool_name, NULL);

	/* Traverse the list of registered pools and locate the
	   one whose name matches */
	for(l = cert_pools; l; l = l->next) {
		pool = (PurpleCertificatePool *)(l->data);

		/* Scheme and name match? */
		if(!g_ascii_strcasecmp(pool->scheme_name, scheme_name) &&
		   !g_ascii_strcasecmp(pool->name, pool_name))
			return pool;
	}

	purple_debug_warning("certificate",
			     "CertificatePool %s, %s requested but not found.\n",
			     scheme_name, pool_name);

	/* TODO: Signalling and such? */

	return NULL;

}

GList *
purple_certificate_get_pools(void)
{
	return cert_pools;
}

gboolean
purple_certificate_register_pool(PurpleCertificatePool *pool)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(pool->scheme_name, FALSE);
	g_return_val_if_fail(pool->name, FALSE);
	g_return_val_if_fail(pool->fullname, FALSE);

	/* Make sure no pools are registered under this name */
	if (purple_certificate_find_pool(pool->scheme_name, pool->name)) {
		return FALSE;
	}

	/* Initialize the pool if needed */
	if (pool->init) {
		gboolean success;

		success = pool->init();
		if (!success)
			return FALSE;
	}

	/* Register the Pool */
	cert_pools = g_list_prepend(cert_pools, pool);

	/* TODO: Emit a signal that the pool got registered */

	PURPLE_DBUS_REGISTER_POINTER(pool, PurpleCertificatePool);
	purple_signal_register(pool, /* Signals emitted from pool */
			       "certificate-stored",
			       purple_marshal_VOID__POINTER_POINTER,
			       NULL, /* No callback return value */
			       2,    /* Two non-data arguments */
			       purple_value_new(PURPLE_TYPE_SUBTYPE,
						PURPLE_SUBTYPE_CERTIFICATEPOOL),
			       purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(pool, /* Signals emitted from pool */
			       "certificate-deleted",
			       purple_marshal_VOID__POINTER_POINTER,
			       NULL, /* No callback return value */
			       2,    /* Two non-data arguments */
			       purple_value_new(PURPLE_TYPE_SUBTYPE,
						PURPLE_SUBTYPE_CERTIFICATEPOOL),
			       purple_value_new(PURPLE_TYPE_STRING));

	purple_debug_info("certificate",
		  "CertificatePool %s registered\n",
		  pool->name);

	return TRUE;
}

gboolean
purple_certificate_unregister_pool(PurpleCertificatePool *pool)
{
	if (NULL == pool) {
		purple_debug_warning("certificate",
				     "Attempting to unregister NULL pool\n");
		return FALSE;
	}

	/* Check that the pool is registered */
	if (!g_list_find(cert_pools, pool)) {
		purple_debug_warning("certificate",
				     "Pool to unregister isn't registered!\n");

		return FALSE;
	}

	/* Uninit the pool if needed */
	PURPLE_DBUS_UNREGISTER_POINTER(pool);
	if (pool->uninit) {
		pool->uninit();
	}

	cert_pools = g_list_remove(cert_pools, pool);

	/* TODO: Signalling? */
	purple_signal_unregister(pool, "certificate-stored");
	purple_signal_unregister(pool, "certificate-deleted");

	purple_debug_info("certificate",
			  "CertificatePool %s unregistered\n",
			  pool->name);
	return TRUE;
}

/****************************************************************************/
/* Scheme-specific functions                                                */
/****************************************************************************/

void
purple_certificate_display_x509(PurpleCertificate *crt)
{
	gchar *sha_asc;
	GByteArray *sha_bin;
	gchar *cn;
	time_t activation, expiration;
	gchar *activ_str, *expir_str;
	gchar *secondary;

	/* Pull out the SHA1 checksum */
	sha_bin = purple_certificate_get_fingerprint_sha1(crt);
	/* Now decode it for display */
	sha_asc = purple_base16_encode_chunked(sha_bin->data,
					       sha_bin->len);

	/* Get the cert Common Name */
	/* TODO: Will break on CA certs */
	cn = purple_certificate_get_subject_name(crt);

	/* Get the certificate times */
	/* TODO: Check the times against localtime */
	/* TODO: errorcheck? */
	if (!purple_certificate_get_times(crt, &activation, &expiration)) {
		purple_debug_error("certificate",
				   "Failed to get certificate times!\n");
		activation = expiration = 0;
	}
	activ_str = g_strdup(ctime(&activation));
	expir_str = g_strdup(ctime(&expiration));

	/* Make messages */
	secondary = g_strdup_printf(_("Common name: %s\n\n"
								  "Fingerprint (SHA1): %s\n\n"
								  "Activation date: %s\n"
								  "Expiration date: %s\n"),
								cn ? cn : "(null)",
								sha_asc ? sha_asc : "(null)",
								activ_str ? activ_str : "(null)",
								expir_str ? expir_str : "(null)");

	/* Make a semi-pretty display */
	purple_notify_info(
		NULL,         /* TODO: Find what the handle ought to be */
		_("Certificate Information"),
		"",
		secondary);

	/* Cleanup */
	g_free(cn);
	g_free(secondary);
	g_free(sha_asc);
	g_free(activ_str);
	g_free(expir_str);
	g_byte_array_free(sha_bin, TRUE);
}

void purple_certificate_add_ca_search_path(const char *path)
{
	if (g_list_find_custom(x509_ca_paths, path, (GCompareFunc)strcmp))
		return;
	x509_ca_paths = g_list_append(x509_ca_paths, g_strdup(path));
}

