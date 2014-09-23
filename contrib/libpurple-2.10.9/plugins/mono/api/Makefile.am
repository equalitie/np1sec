monodir=$(libdir)/purple-$(PURPLE_MAJOR_VERSION)

mono_sources = \
	BlistNode.cs \
	BuddyList.cs \
	Buddy.cs \
	Contact.cs \
	Debug.cs \
	Event.cs \
	PurplePlugin.cs \
	Group.cs \
	Signal.cs \
	Status.cs

EXTRA_DIST = $(mono_sources)

mono_SCRIPTS = PurpleAPI.dll

mono_build_sources = $(addprefix $(srcdir)/, $(mono_sources))

all: $(mono_SCRIPTS)

$(mono_SCRIPTS): $(mono_build_sources)
	mcs -t:library -out:$(mono_SCRIPTS) $(mono_build_sources)

clean-local:
	rm -rf $(mono_SCRIPTS)
