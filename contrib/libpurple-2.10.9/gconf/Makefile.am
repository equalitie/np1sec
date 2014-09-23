schemadir = @GCONF_SCHEMA_FILE_DIR@

EXTRA_DIST = purple.schemas.in

if INSTALL_I18N
schema_in_files = purple.schemas.in
schema_DATA = $(schema_in_files:.schemas.in=.schemas)
@INTLTOOL_SCHEMAS_RULE@

if GCONF_SCHEMAS_INSTALL
install-data-local:
	GCONF_CONFIG_SOURCE=$(GCONF_SCHEMA_CONFIG_SOURCE) $(GCONFTOOL) --makefile-install-rule $(schema_DATA) 2>&1 | \
		grep -v "^WARNING: failed to install schema" | grep -v "^Attached schema" 1>&2
else
install-data-local:
endif #GCONF_SCHEMAS_INSTALL

endif #INSTALL_I18N
