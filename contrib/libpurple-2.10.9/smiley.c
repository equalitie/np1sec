/**
 * @file smiley.c Simley API
 * @ingroup core
 */

/* purple
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
#include "dbus-maybe.h"
#include "debug.h"
#include "imgstore.h"
#include "smiley.h"
#include "util.h"
#include "xmlnode.h"

/**************************************************************************/
/* Main structures, members and constants                                 */
/**************************************************************************/

struct _PurpleSmiley
{
	GObject parent;
	PurpleStoredImage *img;        /**< The id of the stored image with the
	                                    the smiley data.        */
	char *shortcut;                /**< Shortcut associated with the custom
	                                    smiley. This field will work as a
	                                    unique key by this API. */
	char *checksum;                /**< The smiley checksum.        */
};

struct _PurpleSmileyClass
{
	GObjectClass parent_class;
};

static GHashTable *smiley_shortcut_index = NULL; /* shortcut (char *) => smiley (PurpleSmiley*) */
static GHashTable *smiley_checksum_index = NULL; /* checksum (char *) => smiley (PurpleSmiley*) */

static guint save_timer = 0;
static gboolean smileys_loaded = FALSE;
static char *smileys_dir = NULL;

#define SMILEYS_DEFAULT_FOLDER			"custom_smiley"
#define SMILEYS_LOG_ID				"smileys"

#define XML_FILE_NAME				"smileys.xml"

#define XML_ROOT_TAG				"smileys"
#define XML_PROFILE_TAG			"profile"
#define XML_PROFILE_NAME_ATTRIB_TAG		"name"
#define XML_ACCOUNT_TAG			"account"
#define XML_ACCOUNT_USERID_ATTRIB_TAG		"userid"
#define XML_SMILEY_SET_TAG			"smiley_set"
#define XML_SMILEY_TAG				"smiley"
#define XML_SHORTCUT_ATTRIB_TAG		"shortcut"
#define XML_CHECKSUM_ATRIB_TAG			"checksum"
#define XML_FILENAME_ATRIB_TAG			"filename"


/******************************************************************************
 * XML descriptor file layout                                                 *
 ******************************************************************************
 *
 * Although we are creating the profile XML structure here, now we
 * won't handle it.
 * So, we just add one profile named "default" that has no associated
 * account elements, and have only the smiley_set that will contain
 * all existent custom smiley.
 *
 * It's our "Highlander Profile" :-)
 *
 ******************************************************************************
 *
 * <smileys>
 *   <profile name="john.doe">
 *     <account userid="john.doe@jabber.org">
 *     <account userid="john.doe@gmail.com">
 *     <smiley_set>
 *       <smiley shortcut="aaa" checksum="xxxxxxxx" filename="file_name1.gif"/>
 *       <smiley shortcut="bbb" checksum="yyyyyyy" filename="file_name2.gif"/>
 *     </smiley_set>
 *   </profile>
 * </smiley>
 *
 *****************************************************************************/


/*********************************************************************
 * Forward declarations                                              *
 *********************************************************************/

static gboolean read_smiley_file(const char *path, guchar **data, size_t *len);

static char *get_file_full_path(const char *filename);

static PurpleSmiley *purple_smiley_create(const char *shortcut);

static void purple_smiley_load_file(const char *shortcut, const char *checksum,
		const char *filename);

static void
purple_smiley_set_data_impl(PurpleSmiley *smiley, guchar *smiley_data,
		size_t smiley_data_len);

static void
purple_smiley_data_store(PurpleStoredImage *stored_img);

static void
purple_smiley_data_unstore(const char *filename);

/*********************************************************************
 * Writing to disk                                                   *
 *********************************************************************/

static xmlnode *
smiley_to_xmlnode(PurpleSmiley *smiley)
{
	xmlnode *smiley_node = NULL;

	smiley_node = xmlnode_new(XML_SMILEY_TAG);

	if (!smiley_node)
		return NULL;

	xmlnode_set_attrib(smiley_node, XML_SHORTCUT_ATTRIB_TAG,
			smiley->shortcut);

	xmlnode_set_attrib(smiley_node, XML_CHECKSUM_ATRIB_TAG,
			smiley->checksum);

	xmlnode_set_attrib(smiley_node, XML_FILENAME_ATRIB_TAG,
			purple_imgstore_get_filename(smiley->img));

	return smiley_node;
}

static void
add_smiley_to_main_node(gpointer key, gpointer value, gpointer user_data)
{
	xmlnode *child_node;

	child_node = smiley_to_xmlnode(value);
	xmlnode_insert_child((xmlnode*)user_data, child_node);
}

static xmlnode *
smileys_to_xmlnode(void)
{
	xmlnode *root_node, *profile_node, *smileyset_node;

	root_node = xmlnode_new(XML_ROOT_TAG);
	xmlnode_set_attrib(root_node, "version", "1.0");

	/* See the top comments above to understand why initial tag elements
	 * are not being considered by now. */
	profile_node = xmlnode_new(XML_PROFILE_TAG);
	if (profile_node) {
		xmlnode_set_attrib(profile_node, XML_PROFILE_NAME_ATTRIB_TAG, "Default");
		xmlnode_insert_child(root_node, profile_node);

		smileyset_node = xmlnode_new(XML_SMILEY_SET_TAG);
		if (smileyset_node) {
			xmlnode_insert_child(profile_node, smileyset_node);
			g_hash_table_foreach(smiley_shortcut_index, add_smiley_to_main_node, smileyset_node);
		}
	}

	return root_node;
}

static void
sync_smileys(void)
{
	xmlnode *root_node;
	char *data;

	if (!smileys_loaded) {
		purple_debug_error(SMILEYS_LOG_ID, "Attempted to save smileys before it "
						 "was read!\n");
		return;
	}

	root_node = smileys_to_xmlnode();
	data = xmlnode_to_formatted_str(root_node, NULL);
	purple_util_write_data_to_file(XML_FILE_NAME, data, -1);

	g_free(data);
	xmlnode_free(root_node);
}

static gboolean
save_smileys_cb(gpointer data)
{
	sync_smileys();
	save_timer = 0;
	return FALSE;
}

static void
purple_smileys_save(void)
{
	if (save_timer == 0)
		save_timer = purple_timeout_add_seconds(5, save_smileys_cb, NULL);
}


/*********************************************************************
 * Reading from disk                                                 *
 *********************************************************************/

static void
parse_smiley(xmlnode *smiley_node)
{
	const char *shortcut = NULL;
	const char *checksum = NULL;
	const char *filename = NULL;

	shortcut = xmlnode_get_attrib(smiley_node, XML_SHORTCUT_ATTRIB_TAG);
	checksum = xmlnode_get_attrib(smiley_node, XML_CHECKSUM_ATRIB_TAG);
	filename = xmlnode_get_attrib(smiley_node, XML_FILENAME_ATRIB_TAG);

	if ((shortcut == NULL) || (checksum == NULL) || (filename == NULL))
		return;

	purple_smiley_load_file(shortcut, checksum, filename);
}

static void
purple_smileys_load(void)
{
	xmlnode *root_node, *profile_node;
	xmlnode *smileyset_node = NULL;
	xmlnode *smiley_node;

	smileys_loaded = TRUE;

	root_node = purple_util_read_xml_from_file(XML_FILE_NAME,
			_(SMILEYS_LOG_ID));

	if (root_node == NULL)
		return;

	/* See the top comments above to understand why initial tag elements
	 * are not being considered by now. */
	profile_node = xmlnode_get_child(root_node, XML_PROFILE_TAG);
	if (profile_node)
		smileyset_node = xmlnode_get_child(profile_node, XML_SMILEY_SET_TAG);

	if (smileyset_node) {
		smiley_node = xmlnode_get_child(smileyset_node, XML_SMILEY_TAG);
		for (; smiley_node != NULL;
				smiley_node = xmlnode_get_next_twin(smiley_node)) {
			parse_smiley(smiley_node);
		}
	}

	xmlnode_free(root_node);
}

/*********************************************************************
 * GObject Stuff                                                     *
 *********************************************************************/
enum
{
	PROP_0,
	PROP_SHORTCUT,
	PROP_IMGSTORE
};

#define PROP_SHORTCUT_S "shortcut"
#define PROP_IMGSTORE_S "image"

enum
{
	SIG_DESTROY,
	SIG_LAST
};

static guint signals[SIG_LAST];
static GObjectClass *parent_class;

static void
purple_smiley_init(GTypeInstance *instance, gpointer klass)
{
	PurpleSmiley *smiley = PURPLE_SMILEY(instance);
	PURPLE_DBUS_REGISTER_POINTER(smiley, PurpleSmiley);
}

static void
purple_smiley_get_property(GObject *object, guint param_id, GValue *value,
		GParamSpec *spec)
{
	PurpleSmiley *smiley = PURPLE_SMILEY(object);
	switch (param_id) {
		case PROP_SHORTCUT:
			g_value_set_string(value, smiley->shortcut);
			break;
		case PROP_IMGSTORE:
			g_value_set_pointer(value, smiley->img);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, param_id, spec);
			break;
	}
}

static void
purple_smiley_set_property(GObject *object, guint param_id, const GValue *value,
		GParamSpec *spec)
{
	PurpleSmiley *smiley = PURPLE_SMILEY(object);
	switch (param_id) {
		case PROP_SHORTCUT:
			{
				const char *shortcut = g_value_get_string(value);
				purple_smiley_set_shortcut(smiley, shortcut);
			}
			break;
		case PROP_IMGSTORE:
			{
				PurpleStoredImage *img = g_value_get_pointer(value);

				purple_imgstore_unref(smiley->img);
				g_free(smiley->checksum);

				smiley->img = img;
				if (img) {
					smiley->checksum = purple_util_get_image_checksum(
							purple_imgstore_get_data(img),
							purple_imgstore_get_size(img));
					purple_smiley_data_store(img);
				} else {
					smiley->checksum = NULL;
				}

				g_object_notify(object, PROP_IMGSTORE_S);
			}
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, param_id, spec);
			break;
	}
}

static void
purple_smiley_finalize(GObject *obj)
{
	PurpleSmiley *smiley = PURPLE_SMILEY(obj);

	if (g_hash_table_lookup(smiley_shortcut_index, smiley->shortcut)) {
		g_hash_table_remove(smiley_shortcut_index, smiley->shortcut);
		g_hash_table_remove(smiley_checksum_index, smiley->checksum);
	}

	g_free(smiley->shortcut);
	g_free(smiley->checksum);
	if (smiley->img)
		purple_smiley_data_unstore(purple_imgstore_get_filename(smiley->img));
	purple_imgstore_unref(smiley->img);

	PURPLE_DBUS_UNREGISTER_POINTER(smiley);

	purple_smileys_save();
}

static void
purple_smiley_dispose(GObject *gobj)
{
	g_signal_emit(gobj, signals[SIG_DESTROY], 0);
	parent_class->dispose(gobj);
}

static void
purple_smiley_class_init(PurpleSmileyClass *klass)
{
	GObjectClass *gobj_class = G_OBJECT_CLASS(klass);
	GParamSpec *pspec;

	parent_class = g_type_class_peek_parent(klass);

	gobj_class->get_property = purple_smiley_get_property;
	gobj_class->set_property = purple_smiley_set_property;
	gobj_class->finalize = purple_smiley_finalize;
	gobj_class->dispose = purple_smiley_dispose;

	/* Shortcut */
	pspec = g_param_spec_string(PROP_SHORTCUT_S, _("Shortcut"),
			_("The text-shortcut for the smiley"),
			NULL,
			G_PARAM_READWRITE);
	g_object_class_install_property(gobj_class, PROP_SHORTCUT, pspec);

	/* Stored Image */
	pspec = g_param_spec_pointer(PROP_IMGSTORE_S, _("Stored Image"),
			_("Stored Image. (that'll have to do for now)"),
			G_PARAM_READWRITE);
	g_object_class_install_property(gobj_class, PROP_IMGSTORE, pspec);

	signals[SIG_DESTROY] = g_signal_new("destroy",
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_LAST,
			0, NULL, NULL,
			g_cclosure_marshal_VOID__VOID,
			G_TYPE_NONE, 0);
}

GType
purple_smiley_get_type(void)
{
	static GType type = 0;

	if(type == 0) {
		static const GTypeInfo info = {
			sizeof(PurpleSmileyClass),
			NULL,
			NULL,
			(GClassInitFunc)purple_smiley_class_init,
			NULL,
			NULL,
			sizeof(PurpleSmiley),
			0,
			purple_smiley_init,
			NULL,
		};

		type = g_type_register_static(G_TYPE_OBJECT,
				"PurpleSmiley",
				&info, 0);
	}

	return type;
}

/*********************************************************************
 * Other Stuff                                                       *
 *********************************************************************/

static char *get_file_full_path(const char *filename)
{
	char *path;

	path = g_build_filename(purple_smileys_get_storing_dir(), filename, NULL);

	if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
		g_free(path);
		return NULL;
	}

	return path;
}

static void
purple_smiley_load_file(const char *shortcut, const char *checksum, const char *filename)
{
	PurpleSmiley *smiley = NULL;
	guchar *smiley_data;
	size_t smiley_data_len;
	char *fullpath = NULL;

	g_return_if_fail(shortcut  != NULL);
	g_return_if_fail(checksum  != NULL);
	g_return_if_fail(filename != NULL);

	fullpath = get_file_full_path(filename);
	if (!fullpath) {
		purple_debug_error(SMILEYS_LOG_ID, "Path for filename %s doesn't exist\n", filename);
		return;
	}

	smiley = purple_smiley_create(shortcut);
	if (!smiley) {
		g_free(fullpath);
		return;
	}

	smiley->checksum = g_strdup(checksum);

	if (read_smiley_file(fullpath, &smiley_data, &smiley_data_len))
		purple_smiley_set_data_impl(smiley, smiley_data,
				smiley_data_len);
	else
		purple_smiley_delete(smiley);

	g_free(fullpath);

}

static void
purple_smiley_data_store(PurpleStoredImage *stored_img)
{
	const char *dirname;
	char *path;
	FILE *file = NULL;

	g_return_if_fail(stored_img != NULL);

	if (!smileys_loaded)
		return;

	dirname  = purple_smileys_get_storing_dir();
	path = g_build_filename(dirname, purple_imgstore_get_filename(stored_img), NULL);

	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR)) {
		purple_debug_info(SMILEYS_LOG_ID, "Creating smileys directory.\n");

		if (g_mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
			purple_debug_error(SMILEYS_LOG_ID,
			                   "Unable to create directory %s: %s\n",
			                   dirname, g_strerror(errno));
		}
	}

	if ((file = g_fopen(path, "wb")) != NULL) {
		if (!fwrite(purple_imgstore_get_data(stored_img),
				purple_imgstore_get_size(stored_img), 1, file)) {
			purple_debug_error(SMILEYS_LOG_ID, "Error writing %s: %s\n",
			                   path, g_strerror(errno));
		} else {
			purple_debug_info(SMILEYS_LOG_ID, "Wrote cache file: %s\n", path);
		}

		fclose(file);
	} else {
		purple_debug_error(SMILEYS_LOG_ID, "Unable to create file %s: %s\n",
		                   path, g_strerror(errno));
		g_free(path);

		return;
	}

	g_free(path);
}

static void
purple_smiley_data_unstore(const char *filename)
{
	const char *dirname;
	char *path;

	g_return_if_fail(filename != NULL);

	dirname  = purple_smileys_get_storing_dir();
	path = g_build_filename(dirname, filename, NULL);

	if (g_file_test(path, G_FILE_TEST_EXISTS)) {
		if (g_unlink(path))
			purple_debug_error(SMILEYS_LOG_ID, "Failed to delete %s: %s\n",
			                   path, g_strerror(errno));
		else
			purple_debug_info(SMILEYS_LOG_ID, "Deleted cache file: %s\n", path);
	}

	g_free(path);
}

static gboolean
read_smiley_file(const char *path, guchar **data, size_t *len)
{
	GError *err = NULL;

	if (!g_file_get_contents(path, (gchar **)data, len, &err)) {
		purple_debug_error(SMILEYS_LOG_ID, "Error reading %s: %s\n",
				path, err->message);
		g_error_free(err);

		return FALSE;
	}

	return TRUE;
}

static PurpleStoredImage *
purple_smiley_data_new(guchar *smiley_data, size_t smiley_data_len)
{
	char *filename;
	PurpleStoredImage *stored_img;

	g_return_val_if_fail(smiley_data != NULL,   NULL);
	g_return_val_if_fail(smiley_data_len  > 0,  NULL);

	filename = purple_util_get_image_filename(smiley_data, smiley_data_len);

	if (filename == NULL) {
		g_free(smiley_data);
		return NULL;
	}

	stored_img = purple_imgstore_add(smiley_data, smiley_data_len, filename);

	g_free(filename);

	return stored_img;
}

static void
purple_smiley_set_data_impl(PurpleSmiley *smiley, guchar *smiley_data,
				size_t smiley_data_len)
{
	PurpleStoredImage *old_img, *new_img;
	const char *old_filename = NULL;
	const char *new_filename = NULL;

	g_return_if_fail(smiley     != NULL);
	g_return_if_fail(smiley_data != NULL);
	g_return_if_fail(smiley_data_len > 0);

	old_img = smiley->img;

	new_img = purple_smiley_data_new(smiley_data, smiley_data_len);

	g_object_set(G_OBJECT(smiley), PROP_IMGSTORE_S, new_img, NULL);

	/* If the old and new image files have different names we need
	 * to unstore old image file. */
	if (!old_img)
		return;

	old_filename = purple_imgstore_get_filename(old_img);
	new_filename = purple_imgstore_get_filename(smiley->img);

	if (g_ascii_strcasecmp(old_filename, new_filename))
		purple_smiley_data_unstore(old_filename);
	purple_imgstore_unref(old_img);
}


/*****************************************************************************
 * Public API functions                                                      *
 *****************************************************************************/

static PurpleSmiley *
purple_smiley_create(const char *shortcut)
{
	PurpleSmiley *smiley;

	smiley = PURPLE_SMILEY(g_object_new(PURPLE_TYPE_SMILEY, PROP_SHORTCUT_S, shortcut, NULL));

	return smiley;
}

PurpleSmiley *
purple_smiley_new(PurpleStoredImage *img, const char *shortcut)
{
	PurpleSmiley *smiley = NULL;

	g_return_val_if_fail(shortcut  != NULL, NULL);
	g_return_val_if_fail(img       != NULL, NULL);

	smiley = purple_smileys_find_by_shortcut(shortcut);
	if (smiley)
		return smiley;

	smiley = purple_smiley_create(shortcut);
	if (!smiley)
		return NULL;

	g_object_set(G_OBJECT(smiley), PROP_IMGSTORE_S, img, NULL);

	return smiley;
}

static PurpleSmiley *
purple_smiley_new_from_stream(const char *shortcut, guchar *smiley_data,
			size_t smiley_data_len)
{
	PurpleSmiley *smiley;

	g_return_val_if_fail(shortcut  != NULL,    NULL);
	g_return_val_if_fail(smiley_data != NULL,  NULL);
	g_return_val_if_fail(smiley_data_len  > 0, NULL);

	smiley = purple_smileys_find_by_shortcut(shortcut);
	if (smiley)
		return smiley;

	/* purple_smiley_create() sets shortcut */
	smiley = purple_smiley_create(shortcut);
	if (!smiley)
		return NULL;

	purple_smiley_set_data_impl(smiley, smiley_data, smiley_data_len);

	purple_smiley_data_store(smiley->img);

	return smiley;
}

PurpleSmiley *
purple_smiley_new_from_file(const char *shortcut, const char *filepath)
{
	PurpleSmiley *smiley = NULL;
	guchar *smiley_data;
	size_t smiley_data_len;

	g_return_val_if_fail(shortcut  != NULL,  NULL);
	g_return_val_if_fail(filepath != NULL,  NULL);

	if (read_smiley_file(filepath, &smiley_data, &smiley_data_len)) {
		smiley = purple_smiley_new_from_stream(shortcut, smiley_data,
				smiley_data_len);
	}

	return smiley;
}

void
purple_smiley_delete(PurpleSmiley *smiley)
{
	g_return_if_fail(smiley != NULL);

	g_object_unref(smiley);
}

gboolean
purple_smiley_set_shortcut(PurpleSmiley *smiley, const char *shortcut)
{
	g_return_val_if_fail(smiley  != NULL, FALSE);
	g_return_val_if_fail(shortcut != NULL, FALSE);

	/* Check out whether the new shortcut is already being used. */
	if (g_hash_table_lookup(smiley_shortcut_index, shortcut))
		return FALSE;

	/* Remove the old shortcut. */
	if (smiley->shortcut)
		g_hash_table_remove(smiley_shortcut_index, smiley->shortcut);

	/* Insert the new shortcut. */
	g_hash_table_insert(smiley_shortcut_index, g_strdup(shortcut), smiley);

	g_free(smiley->shortcut);
	smiley->shortcut = g_strdup(shortcut);

	g_object_notify(G_OBJECT(smiley), PROP_SHORTCUT_S);

	purple_smileys_save();

	return TRUE;
}

void
purple_smiley_set_data(PurpleSmiley *smiley, guchar *smiley_data,
			   size_t smiley_data_len)
{
	g_return_if_fail(smiley     != NULL);
	g_return_if_fail(smiley_data != NULL);
	g_return_if_fail(smiley_data_len > 0);

	/* Remove the previous entry */
	g_hash_table_remove(smiley_checksum_index, smiley->checksum);

	/* Update the file data. This also updates the checksum. */
	purple_smiley_set_data_impl(smiley, smiley_data, smiley_data_len);

	/* Reinsert the index item. */
	g_hash_table_insert(smiley_checksum_index, g_strdup(smiley->checksum), smiley);

	purple_smileys_save();
}

PurpleStoredImage *
purple_smiley_get_stored_image(const PurpleSmiley *smiley)
{
	return purple_imgstore_ref(smiley->img);
}

const char *purple_smiley_get_shortcut(const PurpleSmiley *smiley)
{
	g_return_val_if_fail(smiley != NULL, NULL);

	return smiley->shortcut;
}

const char *
purple_smiley_get_checksum(const PurpleSmiley *smiley)
{
	g_return_val_if_fail(smiley != NULL, NULL);

	return smiley->checksum;
}

gconstpointer
purple_smiley_get_data(const PurpleSmiley *smiley, size_t *len)
{
	g_return_val_if_fail(smiley != NULL, NULL);

	if (smiley->img) {
		if (len != NULL)
			*len = purple_imgstore_get_size(smiley->img);

		return purple_imgstore_get_data(smiley->img);
	}

	return NULL;
}

const char *
purple_smiley_get_extension(const PurpleSmiley *smiley)
{
	if (smiley->img != NULL)
		return purple_imgstore_get_extension(smiley->img);

	return NULL;
}

char *purple_smiley_get_full_path(PurpleSmiley *smiley)
{
	g_return_val_if_fail(smiley != NULL, NULL);

	if (smiley->img == NULL)
		return NULL;

	return get_file_full_path(purple_imgstore_get_filename(smiley->img));
}

static void add_smiley_to_list(gpointer key, gpointer value, gpointer user_data)
{
	GList** returninglist = (GList**)user_data;

	*returninglist = g_list_append(*returninglist, value);
}

GList *
purple_smileys_get_all(void)
{
	GList *returninglist = NULL;

	g_hash_table_foreach(smiley_shortcut_index, add_smiley_to_list, &returninglist);

	return returninglist;
}

PurpleSmiley *
purple_smileys_find_by_shortcut(const char *shortcut)
{
	g_return_val_if_fail(shortcut != NULL, NULL);

	return g_hash_table_lookup(smiley_shortcut_index, shortcut);
}

PurpleSmiley *
purple_smileys_find_by_checksum(const char *checksum)
{
	g_return_val_if_fail(checksum != NULL, NULL);

	return g_hash_table_lookup(smiley_checksum_index, checksum);
}

const char *
purple_smileys_get_storing_dir(void)
{
	return smileys_dir;
}

void
purple_smileys_init(void)
{
	smiley_shortcut_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	smiley_checksum_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	smileys_dir = g_build_filename(purple_user_dir(), SMILEYS_DEFAULT_FOLDER, NULL);

	purple_smileys_load();
}

void
purple_smileys_uninit(void)
{
	if (save_timer != 0) {
		purple_timeout_remove(save_timer);
		save_timer = 0;
		sync_smileys();
	}

	g_hash_table_destroy(smiley_shortcut_index);
	g_hash_table_destroy(smiley_checksum_index);
	g_free(smileys_dir);
}

