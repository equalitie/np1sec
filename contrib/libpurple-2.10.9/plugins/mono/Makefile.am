SUBDIRS = api loader

mono_sources = GetBuddyBack.cs \
			   MPlugin.cs

EXTRA_DIST = $(mono_sources)

monodir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)
mono_SCRIPTS = MPlugin.dll GetBuddyBack.dll
mono_build_sources = $(addprefix $(srcdir)/, $(mono_sources))

all: $(mono_SCRIPTS)

SUFFIXES = .cs .dll
.cs.dll: api/PurpleAPI.dll $(mono_build_sources)
	mcs -t:library -lib:./api -out:$@ -r:PurpleAPI.dll $<

clean-local:
	rm -f $(mono_SCRIPTS)
