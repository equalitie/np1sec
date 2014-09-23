#include "module.h"

MODULE = Purple::Conversation  PACKAGE = Purple  PREFIX = purple_
PROTOTYPES: ENABLE

BOOT:
{
	HV *type_stash = gv_stashpv("Purple::Conversation::Type", 1);
	HV *update_stash = gv_stashpv("Purple::Conversation::Update::Type", 1);
	HV *typing_stash = gv_stashpv("Purple::Conversation::TypingState", 1);
	HV *flags_stash = gv_stashpv("Purple::Conversation::Flags", 1);
	HV *cbflags_stash = gv_stashpv("Purple::Conversation::ChatBuddy::Flags", 1);

	static const constiv *civ, type_const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_CONV_TYPE_##name}
		const_iv(UNKNOWN),
		const_iv(IM),
		const_iv(CHAT),
		const_iv(MISC),
		const_iv(ANY),
	};
	static const constiv update_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_CONV_UPDATE_##name}
		const_iv(ADD),
		const_iv(REMOVE),
		const_iv(ACCOUNT),
		const_iv(TYPING),
		const_iv(UNSEEN),
		const_iv(LOGGING),
		const_iv(TOPIC),
/*
		const_iv(ONLINE),
		const_iv(OFFLINE),
*/
		const_iv(AWAY),
		const_iv(ICON),
		const_iv(TITLE),
		const_iv(CHATLEFT),
		const_iv(FEATURES),
	};
	static const constiv typing_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_##name}
		const_iv(NOT_TYPING),
		const_iv(TYPING),
		const_iv(TYPED),
	};
	static const constiv flags_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_MESSAGE_##name}
		const_iv(SEND),
		const_iv(RECV),
		const_iv(SYSTEM),
		const_iv(AUTO_RESP),
		const_iv(ACTIVE_ONLY),
		const_iv(NICK),
		const_iv(NO_LOG),
		const_iv(WHISPER),
		const_iv(ERROR),
		const_iv(DELAYED),
		const_iv(RAW),
		const_iv(IMAGES),
		const_iv(NOTIFY),
		const_iv(NO_LINKIFY),
	};
	static const constiv cbflags_const_iv[] = {
#undef const_iv
#define const_iv(name) {#name, (IV)PURPLE_CBFLAGS_##name}
		const_iv(NONE),
		const_iv(VOICE),
		const_iv(HALFOP),
		const_iv(OP),
		const_iv(FOUNDER),
		const_iv(TYPING),
	};

	for (civ = type_const_iv + sizeof(type_const_iv) / sizeof(type_const_iv[0]); civ-- > type_const_iv; )
		newCONSTSUB(type_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = update_const_iv + sizeof(update_const_iv) / sizeof(update_const_iv[0]); civ-- > update_const_iv; )
		newCONSTSUB(update_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = typing_const_iv + sizeof(typing_const_iv) / sizeof(typing_const_iv[0]); civ-- > typing_const_iv; )
		newCONSTSUB(typing_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = flags_const_iv + sizeof(flags_const_iv) / sizeof(flags_const_iv[0]); civ-- > flags_const_iv; )
		newCONSTSUB(flags_stash, (char *)civ->name, newSViv(civ->iv));

	for (civ = cbflags_const_iv + sizeof(cbflags_const_iv) / sizeof(cbflags_const_iv[0]); civ-- > cbflags_const_iv; )
		newCONSTSUB(cbflags_stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_get_ims()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_get_ims(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Conversation")));
	}

void
purple_get_conversations()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_get_conversations(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Conversation")));
	}

void
purple_get_chats()
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_get_chats(); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::Conversation")));
	}

Purple::Conversation
purple_find_conversation_with_account(type, name, account)
	Purple::ConversationType type
	const char *name
	Purple::Account account

MODULE = Purple::Conversation  PACKAGE = Purple::Conversations  PREFIX = purple_conversations_
PROTOTYPES: ENABLE

Purple::Handle
purple_conversations_get_handle()

MODULE = Purple::Conversation  PACKAGE = Purple::Conversation  PREFIX = purple_conversation_
PROTOTYPES: ENABLE

void
purple_conversation_destroy(conv)
	Purple::Conversation conv

Purple::ConversationType
purple_conversation_get_type(conv)
	Purple::Conversation conv

Purple::Account
purple_conversation_get_account(conv)
	Purple::Conversation conv

Purple::Connection
purple_conversation_get_gc(conv)
	Purple::Conversation conv

void
purple_conversation_set_title(conv, title);
	Purple::Conversation conv
	const char * title

const char *
purple_conversation_get_title(conv)
	Purple::Conversation conv

void
purple_conversation_autoset_title(conv)
	Purple::Conversation conv

void
purple_conversation_set_name(conv, name)
	Purple::Conversation conv
	const char *name

const char *
purple_conversation_get_name(conv)
	Purple::Conversation conv

void
purple_conversation_set_logging(conv, log)
	Purple::Conversation conv
	gboolean log

gboolean
purple_conversation_is_logging(conv)
	Purple::Conversation conv

Purple::Conversation::IM
purple_conversation_get_im_data(conv)
	Purple::Conversation conv

Purple::Conversation::Chat
purple_conversation_get_chat_data(conv)
	Purple::Conversation conv

gpointer
purple_conversation_get_data(conv, key)
	Purple::Conversation conv
	const char * key

Purple::ConnectionFlags
purple_conversation_get_features(conv)
	Purple::Conversation conv

gboolean
purple_conversation_has_focus(conv)
	Purple::Conversation conv

void
purple_conversation_update(conv, type)
	Purple::Conversation conv
	Purple::ConvUpdateType type

Purple::Conversation
purple_conversation_new(class, type, account, name)
	Purple::ConversationType type
	Purple::Account account
	const char *name
    C_ARGS:
	type, account, name

void
purple_conversation_set_account(conv, account);
	Purple::Conversation conv
	Purple::Account account

void
purple_conversation_write(conv, who, message, flags, mtime)
	Purple::Conversation conv
	const char *who
	const char *message
	Purple::MessageFlags flags
	time_t mtime

gboolean
purple_conversation_do_command(conv, cmdline, markup, error)
	Purple::Conversation conv
	const char *cmdline
	const char *markup
	char **error

MODULE = Purple::Conversation  PACKAGE = Purple::Conversation::IM  PREFIX = purple_conv_im_
PROTOTYPES: ENABLE

Purple::Conversation
purple_conv_im_get_conversation(im)
	Purple::Conversation::IM im

void
purple_conv_im_set_icon(im, icon)
	Purple::Conversation::IM im
	Purple::Buddy::Icon icon

Purple::Buddy::Icon
purple_conv_im_get_icon(im)
	Purple::Conversation::IM im

void
purple_conv_im_set_typing_state(im, state)
	Purple::Conversation::IM im
	Purple::TypingState state

Purple::TypingState
purple_conv_im_get_typing_state(im)
	Purple::Conversation::IM im

void
purple_conv_im_start_typing_timeout(im, timeout)
	Purple::Conversation::IM im
	int timeout

void
purple_conv_im_stop_typing_timeout(im)
	Purple::Conversation::IM im

guint
purple_conv_im_get_typing_timeout(im)
	Purple::Conversation::IM im

void
purple_conv_im_set_type_again(im, val)
	Purple::Conversation::IM im
	time_t val

time_t
purple_conv_im_get_type_again(im)
	Purple::Conversation::IM im

void
purple_conv_im_start_send_typed_timeout(im)
	Purple::Conversation::IM im

void
purple_conv_im_stop_send_typed_timeout(im)
	Purple::Conversation::IM im

guint
purple_conv_im_get_send_typed_timeout(im)
	Purple::Conversation::IM im

void
purple_conv_im_update_typing(im)
	Purple::Conversation::IM im

void
purple_conv_im_send(im, message)
	Purple::Conversation::IM im
	const char *message

void
purple_conv_im_send_with_flags(im, message, flags)
	Purple::Conversation::IM im
	const char *message
	Purple::MessageFlags flags

void
purple_conv_im_write(im, who, message, flags, mtime)
	Purple::Conversation::IM im
	const char *who
	const char *message
	Purple::MessageFlags flags
	time_t mtime

MODULE = Purple::Conversation  PACKAGE = Purple::Conversation  PREFIX = purple_conv_
PROTOTYPES: ENABLE

gboolean
purple_conv_present_error(who, account, what)
	const char *who
	Purple::Account account
	const char *what

void
purple_conv_custom_smiley_close(conv, smile)
	Purple::Conversation conv
	const char *smile

MODULE = Purple::Conversation  PACKAGE = Purple::Conversation::Chat  PREFIX = purple_conv_chat_
PROTOTYPES: ENABLE

Purple::Conversation
purple_conv_chat_get_conversation(chat)
	Purple::Conversation::Chat chat

void
purple_conv_chat_set_users(chat, users)
	Purple::Conversation::Chat chat
	SV * users
PREINIT:
	GList *l, *t_GL;
	int i, t_len;
PPCODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(users));

	for (i = 0; i <= t_len; i++)
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(users), i, 0)));

	for (l = purple_conv_chat_set_users(chat, t_GL); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListEntry")));
	}

void
purple_conv_chat_get_users(chat)
	Purple::Conversation::Chat chat
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_conv_chat_get_users(chat); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListEntry")));
	}

void
purple_conv_chat_ignore(chat, name)
	Purple::Conversation::Chat chat
	const char *name

void
purple_conv_chat_unignore(chat, name)
	Purple::Conversation::Chat chat
	const char *name

void
purple_conv_chat_set_ignored(chat, ignored)
	Purple::Conversation::Chat chat
	SV * ignored
PREINIT:
	GList *l, *t_GL;
	int i, t_len;
PPCODE:
	t_GL = NULL;
	t_len = av_len((AV *)SvRV(ignored));

	for (i = 0; i <= t_len; i++)
		t_GL = g_list_append(t_GL, SvPVutf8_nolen(*av_fetch((AV *)SvRV(ignored), i, 0)));

	for (l = purple_conv_chat_set_ignored(chat, t_GL); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListEntry")));
	}

void
purple_conv_chat_get_ignored(chat)
	Purple::Conversation::Chat chat
PREINIT:
	GList *l;
PPCODE:
	for (l = purple_conv_chat_get_ignored(chat); l != NULL; l = l->next) {
		XPUSHs(sv_2mortal(purple_perl_bless_object(l->data, "Purple::ListEntry")));
	}

const char *
purple_conv_chat_get_topic(chat)
	Purple::Conversation::Chat chat

void
purple_conv_chat_set_id(chat, id)
	Purple::Conversation::Chat chat
	int id

int
purple_conv_chat_get_id(chat)
	Purple::Conversation::Chat chat

void
purple_conv_chat_send(chat, message)
	Purple::Conversation::Chat chat
	const char * message

void
purple_conv_chat_send_with_flags(chat, message, flags)
	Purple::Conversation::Chat chat
	const char * message
	Purple::MessageFlags flags

void
purple_conv_chat_write(chat, who, message, flags, mtime)
	Purple::Conversation::Chat chat
	const char *who
	const char *message
	Purple::MessageFlags flags
	time_t mtime

void
purple_conv_chat_add_users(chat, users, extra_msgs, flags, new_arrivals)
	Purple::Conversation::Chat chat
	SV * users
	SV * extra_msgs
	SV * flags
	gboolean new_arrivals
PREINIT:
	GList *t_GL_users, *t_GL_extra_msgs, *t_GL_flags;
	int i, t_len;
PPCODE:
	t_GL_users = NULL;
	t_len = av_len((AV *)SvRV(users));

	for (i = 0; i <= t_len; i++)
		t_GL_users = g_list_append(t_GL_users, SvPVutf8_nolen(*av_fetch((AV *)SvRV(users), i, 0)));

	t_GL_flags = NULL;
	t_len = av_len((AV *)SvRV(flags));

	for (i = 0; i <= t_len; i++)
		t_GL_flags = g_list_append(t_GL_flags, SvPVutf8_nolen(*av_fetch((AV *)SvRV(flags), i, 0)));

	t_GL_extra_msgs = NULL;
	t_len = av_len((AV *)SvRV(extra_msgs));

	for (i = 0; i <= t_len; i++)
		t_GL_extra_msgs = g_list_append(t_GL_extra_msgs, SvPVutf8_nolen(*av_fetch((AV *)SvRV(extra_msgs), i, 0)));

	purple_conv_chat_add_users(chat, t_GL_users, t_GL_extra_msgs, t_GL_flags, new_arrivals);

	g_list_free(t_GL_users);
	g_list_free(t_GL_extra_msgs);
	g_list_free(t_GL_flags);

gboolean
purple_conv_chat_find_user(chat, user)
	Purple::Conversation::Chat chat
	const char * user

void purple_conv_chat_clear_users(chat)
	Purple::Conversation::Chat chat

void purple_conv_chat_set_nick(chat, nick)
	Purple::Conversation::Chat chat
	const char * nick

const char *
purple_conv_chat_get_nick(chat)
	Purple::Conversation::Chat chat

Purple::Conversation
purple_find_chat(gc, id)
	Purple::Connection gc
	int id

void purple_conv_chat_left(chat)
	Purple::Conversation::Chat chat

gboolean purple_conv_chat_has_left(chat)
	Purple::Conversation::Chat chat

Purple::Conversation::ChatBuddy
purple_conv_chat_cb_find(chat, name)
	Purple::Conversation::Chat chat
	const char *name

const char *
purple_conv_chat_cb_get_name(cb)
	Purple::Conversation::ChatBuddy cb

void
purple_conv_chat_cb_destroy(cb);
	Purple::Conversation::ChatBuddy cb
