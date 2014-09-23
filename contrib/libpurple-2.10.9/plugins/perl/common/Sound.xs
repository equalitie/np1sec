#include "module.h"

MODULE = Purple::Sound  PACKAGE = Purple::Sound  PREFIX = purple_sound_
PROTOTYPES: ENABLE

BOOT:
{
	HV *stash = gv_stashpv("Purple::SoundEventID", 1);

	static const constiv *civ, const_iv[] = {
#define const_iv(name) {#name, (IV)PURPLE_SOUND_##name}
		const_iv(BUDDY_ARRIVE),
		const_iv(BUDDY_LEAVE),
		const_iv(RECEIVE),
		const_iv(FIRST_RECEIVE),
		const_iv(SEND),
		const_iv(CHAT_JOIN),
		const_iv(CHAT_LEAVE),
		const_iv(CHAT_YOU_SAY),
		const_iv(CHAT_SAY),
		const_iv(POUNCE_DEFAULT),
		const_iv(CHAT_NICK),
	};

	for (civ = const_iv + sizeof(const_iv) / sizeof(const_iv[0]); civ-- > const_iv; )
		newCONSTSUB(stash, (char *)civ->name, newSViv(civ->iv));
}

void
purple_sound_play_event(event, account)
	Purple::SoundEventID event
	Purple::Account account

void
purple_sound_play_file(filename, account)
	const char *filename
	Purple::Account account
