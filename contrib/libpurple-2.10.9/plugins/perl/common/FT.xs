#include "module.h"

MODULE = Purple::Xfer  PACKAGE = Purple::Xfer  PREFIX = purple_xfer_
PROTOTYPES: ENABLE

BOOT:
{
	HV *type_stash = gv_stashpv("Purple::Xfer::Type", 1);
	HV *status_stash = gv_stashpv("Purple::Xfer::Status", 1);

	static const constiv *civ, type_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_XFER_##name}
		const_iv(UNKNOWN),
		const_iv(SEND),
		const_iv(RECEIVE),
	};
	static const constiv status_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_XFER_STATUS_##name}
		const_iv(UNKNOWN),
		const_iv(NOT_STARTED),
		const_iv(ACCEPTED),
		const_iv(STARTED),
		const_iv(DONE),
		const_iv(CANCEL_LOCAL),
		const_iv(CANCEL_REMOTE),
	};

	for (civ = type_const_iv + sizeof(type_const_iv) / sizeof(type_const_iv[0]); civ-- > type_const_iv; )
		newCONSTSUB(type_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = status_const_iv + sizeof(status_const_iv) / sizeof(status_const_iv[0]); civ-- > status_const_iv; )
		newCONSTSUB(status_stash, (char *)civ->name, newSViv(civ->iv));
}

Purple::Xfer
purple_xfer_new(class, account, type, who)
	Purple::Account account
	Purple::XferType type
	const char *who
    C_ARGS:
	account, type, who

void 
purple_xfer_add(xfer)
	Purple::Xfer xfer

void 
purple_xfer_cancel_local(xfer)
	Purple::Xfer xfer

void 
purple_xfer_cancel_remote(xfer)
	Purple::Xfer xfer

void 
purple_xfer_end(xfer)
	Purple::Xfer xfer

void 
purple_xfer_error(type, account, who, msg)
	Purple::XferType type
	Purple::Account account
	const char *who
	const char *msg

Purple::Account
purple_xfer_get_account(xfer)
	Purple::Xfer xfer

size_t 
purple_xfer_get_bytes_remaining(xfer)
	Purple::Xfer xfer

size_t 
purple_xfer_get_bytes_sent(xfer)
	Purple::Xfer xfer

const char *
purple_xfer_get_filename(xfer)
	Purple::Xfer xfer

const char *
purple_xfer_get_local_filename(xfer)
	Purple::Xfer xfer

unsigned int 
purple_xfer_get_local_port(xfer)
	Purple::Xfer xfer

double 
purple_xfer_get_progress(xfer)
	Purple::Xfer xfer

const char *
purple_xfer_get_remote_ip(xfer)
	Purple::Xfer xfer

unsigned int 
purple_xfer_get_remote_port(xfer)
	Purple::Xfer xfer

size_t 
purple_xfer_get_size(xfer)
	Purple::Xfer xfer

Purple::XferStatusType
purple_xfer_get_status(xfer)
	Purple::Xfer xfer

Purple::XferType
purple_xfer_get_type(xfer)
	Purple::Xfer xfer

gboolean 
purple_xfer_is_canceled(xfer)
	Purple::Xfer xfer

gboolean 
purple_xfer_is_completed(xfer)
	Purple::Xfer xfer

ssize_t 
purple_xfer_read(xfer, buffer)
	Purple::Xfer xfer
	guchar **buffer

void 
purple_xfer_ref(xfer)
	Purple::Xfer xfer

void 
purple_xfer_request(xfer)
	Purple::Xfer xfer

void 
purple_xfer_request_accepted(xfer, filename)
	Purple::Xfer xfer
	const char *filename

void 
purple_xfer_request_denied(xfer)
	Purple::Xfer xfer

void 
purple_xfer_set_completed(xfer, completed)
	Purple::Xfer xfer
	gboolean completed

void 
purple_xfer_set_filename(xfer, filename)
	Purple::Xfer xfer
	const char *filename

void 
purple_xfer_set_local_filename(xfer, filename)
	Purple::Xfer xfer
	const char *filename

void 
purple_xfer_set_message(xfer, message)
	Purple::Xfer xfer
	const char *message

void 
purple_xfer_set_size(xfer, size)
	Purple::Xfer xfer
	size_t size

void 
purple_xfer_unref(xfer)
	Purple::Xfer xfer

void 
purple_xfer_update_progress(xfer)
	Purple::Xfer xfer

ssize_t 
purple_xfer_write(xfer, buffer, size)
	Purple::Xfer xfer
	const guchar *buffer
	size_t size

MODULE = Purple::Xfer  PACKAGE = Purple::Xfers  PREFIX = purple_xfers_
PROTOTYPES: ENABLE


