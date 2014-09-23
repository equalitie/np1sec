
/*
  Meanwhile Protocol Plugin for Purple
  Adds Lotus Sametime support to Purple using the Meanwhile library

  Copyright (C) 2004 Christopher (siege) O'Brien <siege@preoccupied.net>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at
  your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301,
  USA.
*/

#include "internal.h"

/* system includes */
#include <stdlib.h>
#include <time.h>

/* glib includes */
#include <glib.h>

/* purple includes */
#include "account.h"
#include "accountopt.h"
#include "circbuffer.h"
#include "conversation.h"
#include "debug.h"
#include "ft.h"
#include "imgstore.h"
#include "mime.h"
#include "notify.h"
#include "plugin.h"
#include "privacy.h"
#include "prpl.h"
#include "request.h"
#include "util.h"
#include "version.h"

/* meanwhile includes */
#include <mw_cipher.h>
#include <mw_common.h>
#include <mw_error.h>
#include <mw_service.h>
#include <mw_session.h>
#include <mw_srvc_aware.h>
#include <mw_srvc_conf.h>
#include <mw_srvc_ft.h>
#include <mw_srvc_im.h>
#include <mw_srvc_place.h>
#include <mw_srvc_resolve.h>
#include <mw_srvc_store.h>
#include <mw_st_list.h>

/* plugin includes */
#include "sametime.h"


/* considering that there's no display of this information for prpls,
   I don't know why I even bother providing these. Oh valiant reader,
   I do it all for you. */
/* scratch that, I just added it to the prpl options panel */
#define PLUGIN_ID        "prpl-meanwhile"
#define PLUGIN_NAME      "Sametime"
#define PLUGIN_SUMMARY   "Sametime Protocol Plugin"
#define PLUGIN_DESC      "Open implementation of a Lotus Sametime client"
#define PLUGIN_AUTHOR    "Christopher (siege) O'Brien <siege@preoccupied.net>"
#define PLUGIN_HOMEPAGE  "http://meanwhile.sourceforge.net/"


/* plugin preference names */
#define MW_PRPL_OPT_BASE          "/plugins/prpl/meanwhile"
#define MW_PRPL_OPT_BLIST_ACTION  MW_PRPL_OPT_BASE "/blist_action"
#define MW_PRPL_OPT_PSYCHIC       MW_PRPL_OPT_BASE "/psychic"
#define MW_PRPL_OPT_FORCE_LOGIN   MW_PRPL_OPT_BASE "/force_login"
#define MW_PRPL_OPT_SAVE_DYNAMIC  MW_PRPL_OPT_BASE "/save_dynamic"


/* stages of connecting-ness */
#define MW_CONNECT_STEPS  11


/* stages of conciousness */
#define MW_STATE_OFFLINE      "offline"
#define MW_STATE_ACTIVE       "active"
#define MW_STATE_AWAY         "away"
#define MW_STATE_BUSY         "dnd"
#define MW_STATE_MESSAGE      "message"
#define MW_STATE_ENLIGHTENED  "buddha"


/* keys to get/set chat information */
#define CHAT_KEY_CREATOR   "chat.creator"
#define CHAT_KEY_NAME      "chat.name"
#define CHAT_KEY_TOPIC     "chat.topic"
#define CHAT_KEY_INVITE    "chat.invite"
#define CHAT_KEY_IS_PLACE  "chat.is_place"


/* key for associating a mwLoginType with a buddy */
#define BUDDY_KEY_CLIENT  "meanwhile.client"

/* store the remote alias so that we can re-create it easily */
#define BUDDY_KEY_NAME    "meanwhile.shortname"

/* enum mwSametimeUserType */
#define BUDDY_KEY_TYPE    "meanwhile.type"


/* key for the real group name for a meanwhile group */
#define GROUP_KEY_NAME    "meanwhile.group"

/* enum mwSametimeGroupType */
#define GROUP_KEY_TYPE    "meanwhile.type"

/* NAB group owning account */
#define GROUP_KEY_OWNER   "meanwhile.account"

/* key gtk blist uses to indicate a collapsed group */
#define GROUP_KEY_COLLAPSED  "collapsed"


/* verification replacement */
#define mwSession_NO_SECRET  "meanwhile.no_secret"


/* keys to get/set purple plugin information */
#define MW_KEY_HOST        "server"
#define MW_KEY_PORT        "port"
#define MW_KEY_FORCE       "force_login"
#define MW_KEY_FAKE_IT     "fake_client_id"
#define MW_KEY_CLIENT      "client_id_val"
#define MW_KEY_MAJOR       "client_major"
#define MW_KEY_MINOR       "client_minor"


/** number of seconds from the first blist change before a save to the
    storage service occurs. */
#define BLIST_SAVE_SECONDS  15


/** the possible buddy list storage settings */
enum blist_choice {
  blist_choice_LOCAL = 1, /**< local only */
  blist_choice_MERGE = 2, /**< merge from server */
  blist_choice_STORE = 3, /**< merge from and save to server */
  blist_choice_SYNCH = 4  /**< sync with server */
};


/** the default blist storage option */
#define BLIST_CHOICE_DEFAULT  blist_choice_SYNCH


/* testing for the above */
#define BLIST_PREF_IS(n) (purple_prefs_get_int(MW_PRPL_OPT_BLIST_ACTION)==(n))
#define BLIST_PREF_IS_LOCAL()  BLIST_PREF_IS(blist_choice_LOCAL)
#define BLIST_PREF_IS_MERGE()  BLIST_PREF_IS(blist_choice_MERGE)
#define BLIST_PREF_IS_STORE()  BLIST_PREF_IS(blist_choice_STORE)
#define BLIST_PREF_IS_SYNCH()  BLIST_PREF_IS(blist_choice_SYNCH)


/* debugging output */
#define DEBUG_ERROR(...)  purple_debug_error(G_LOG_DOMAIN, __VA_ARGS__)
#define DEBUG_INFO(...)   purple_debug_info(G_LOG_DOMAIN, __VA_ARGS__)
#define DEBUG_MISC(...)   purple_debug_misc(G_LOG_DOMAIN, __VA_ARGS__)
#define DEBUG_WARN(...)   purple_debug_warning(G_LOG_DOMAIN, __VA_ARGS__)


/** ensure non-null strings */
#ifndef NSTR
# define NSTR(str) ((str)? (str): "(null)")
#endif


/** calibrates distinct secure channel nomenclature */
static const unsigned char no_secret[] = {
  0x2d, 0x2d, 0x20, 0x73, 0x69, 0x65, 0x67, 0x65,
  0x20, 0x6c, 0x6f, 0x76, 0x65, 0x73, 0x20, 0x6a,
  0x65, 0x6e, 0x6e, 0x69, 0x20, 0x61, 0x6e, 0x64,
  0x20, 0x7a, 0x6f, 0x65, 0x20, 0x2d, 0x2d, 0x00,
};


/** handler IDs from g_log_set_handler in mw_plugin_init */
static guint log_handler[2] = { 0, 0 };


/** the purple plugin data.
    available as gc->proto_data and mwSession_getClientData */
struct mwPurplePluginData {
  struct mwSession *session;

  struct mwServiceAware *srvc_aware;
  struct mwServiceConference *srvc_conf;
  struct mwServiceFileTransfer *srvc_ft;
  struct mwServiceIm *srvc_im;
  struct mwServicePlace *srvc_place;
  struct mwServiceResolve *srvc_resolve;
  struct mwServiceStorage *srvc_store;

  /** map of PurpleGroup:mwAwareList and mwAwareList:PurpleGroup */
  GHashTable *group_list_map;

  /** event id for the buddy list save callback */
  guint save_event;

  /** socket fd */
  int socket;
  gint outpa;  /* like inpa, but the other way */

  /** circular buffer for outgoing data */
  PurpleCircBuffer *sock_buf;

  PurpleConnection *gc;
};


typedef struct {
  PurpleBuddy *buddy;
  PurpleGroup *group;
} BuddyAddData;


/* blist and aware functions */

static void blist_export(PurpleConnection *gc, struct mwSametimeList *stlist);

static void blist_store(struct mwPurplePluginData *pd);

static void blist_schedule(struct mwPurplePluginData *pd);

static void blist_merge(PurpleConnection *gc, struct mwSametimeList *stlist);

static void blist_sync(PurpleConnection *gc, struct mwSametimeList *stlist);

static gboolean buddy_is_external(PurpleBuddy *b);

static void buddy_add(struct mwPurplePluginData *pd, PurpleBuddy *buddy);

static PurpleBuddy *
buddy_ensure(PurpleConnection *gc, PurpleGroup *group,
	     struct mwSametimeUser *stuser);

static void group_add(struct mwPurplePluginData *pd, PurpleGroup *group);

static PurpleGroup *
group_ensure(PurpleConnection *gc, struct mwSametimeGroup *stgroup);

static struct mwAwareList *
list_ensure(struct mwPurplePluginData *pd, PurpleGroup *group);


/* session functions */

static struct mwSession *
gc_to_session(PurpleConnection *gc);

static PurpleConnection *session_to_gc(struct mwSession *session);


/* conference functions */

static struct mwConference *
conf_find_by_id(struct mwPurplePluginData *pd, int id);


/* conversation functions */

struct convo_msg {
  enum mwImSendType type;
  gpointer data;
  GDestroyNotify clear;
};


struct convo_data {
  struct mwConversation *conv;
  GList *queue;   /**< outgoing message queue, list of convo_msg */
};

static void convo_data_new(struct mwConversation *conv);

static void convo_data_free(struct convo_data *conv);

static void convo_features(struct mwConversation *conv);

static PurpleConversation *convo_get_gconv(struct mwConversation *conv);


/* name and id */

struct named_id {
  char *id;
  char *name;
};


/* connection functions */

static void connect_cb(gpointer data, gint source, const gchar *error_message);


/* ----- session ------ */


/** resolves a mwSession from a PurpleConnection */
static struct mwSession *gc_to_session(PurpleConnection *gc) {
  struct mwPurplePluginData *pd;

  g_return_val_if_fail(gc != NULL, NULL);

  pd = gc->proto_data;
  g_return_val_if_fail(pd != NULL, NULL);

  return pd->session;
}


/** resolves a PurpleConnection from a mwSession */
static PurpleConnection *session_to_gc(struct mwSession *session) {
  struct mwPurplePluginData *pd;

  g_return_val_if_fail(session != NULL, NULL);

  pd = mwSession_getClientData(session);
  g_return_val_if_fail(pd != NULL, NULL);

  return pd->gc;
}


static void write_cb(gpointer data, gint source, PurpleInputCondition cond) {
  struct mwPurplePluginData *pd = data;
  PurpleCircBuffer *circ = pd->sock_buf;
  gsize avail;
  int ret;

  DEBUG_INFO("write_cb\n");

  g_return_if_fail(circ != NULL);

  avail = purple_circ_buffer_get_max_read(circ);
  if(BUF_LONG < avail) avail = BUF_LONG;

  while(avail) {
    ret = write(pd->socket, circ->outptr, avail);

    if(ret <= 0)
      break;

    purple_circ_buffer_mark_read(circ, ret);
    avail = purple_circ_buffer_get_max_read(circ);
    if(BUF_LONG < avail) avail = BUF_LONG;
  }

  if(! avail) {
    purple_input_remove(pd->outpa);
    pd->outpa = 0;
  }
}


static int mw_session_io_write(struct mwSession *session,
			       const guchar *buf, gsize len) {
  struct mwPurplePluginData *pd;
  gssize ret = 0;
  int err = 0;

  pd = mwSession_getClientData(session);

  /* socket was already closed. */
  if(pd->socket == 0)
    return 1;

  if(pd->outpa) {
    DEBUG_INFO("already pending INPUT_WRITE, buffering\n");
    purple_circ_buffer_append(pd->sock_buf, buf, len);
    return 0;
  }

  while(len) {
    ret = write(pd->socket, buf, (len > BUF_LEN)? BUF_LEN: len);

    if(ret <= 0)
      break;

    len -= ret;
    buf += ret;
  }

  if(ret <= 0)
    err = errno;

  if(err == EAGAIN) {
    /* append remainder to circular buffer */
    DEBUG_INFO("EAGAIN\n");
    purple_circ_buffer_append(pd->sock_buf, buf, len);
    pd->outpa = purple_input_add(pd->socket, PURPLE_INPUT_WRITE, write_cb, pd);

  } else if(len > 0) {
	gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"),
			g_strerror(errno));
    DEBUG_ERROR("write returned %" G_GSSIZE_FORMAT ", %" G_GSIZE_FORMAT
			" bytes left unwritten\n", ret, len);
    purple_connection_error_reason(pd->gc,
                                   PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                   tmp);
	g_free(tmp);

#if 0
    close(pd->socket);
    pd->socket = 0;
#endif

    return -1;
  }

  return 0;
}


static void mw_session_io_close(struct mwSession *session) {
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;

  pd = mwSession_getClientData(session);
  g_return_if_fail(pd != NULL);

  gc = pd->gc;

  if(pd->outpa) {
    purple_input_remove(pd->outpa);
    pd->outpa = 0;
  }

  if(pd->socket) {
    close(pd->socket);
    pd->socket = 0;
  }

  if(gc->inpa) {
    purple_input_remove(gc->inpa);
    gc->inpa = 0;
  }
}


static void mw_session_clear(struct mwSession *session) {
  ; /* nothing for now */
}


/* ----- aware list ----- */


static void blist_resolve_alias_cb(struct mwServiceResolve *srvc,
				   guint32 id, guint32 code, GList *results,
				   gpointer data) {
  struct mwResolveResult *result;
  struct mwResolveMatch *match;

  g_return_if_fail(results != NULL);

  result = results->data;
  g_return_if_fail(result != NULL);
  g_return_if_fail(result->matches != NULL);

  match = result->matches->data;
  g_return_if_fail(match != NULL);

  purple_blist_server_alias_buddy(data, match->name);
  purple_blist_node_set_string(data, BUDDY_KEY_NAME, match->name);
}


static void mw_aware_list_on_aware(struct mwAwareList *list,
				   struct mwAwareSnapshot *aware) {

  PurpleConnection *gc;
  PurpleAccount *acct;

  struct mwPurplePluginData *pd;
  guint32 idle;
  guint stat;
  const char *id;
  const char *status = MW_STATE_ACTIVE;

  gc = mwAwareList_getClientData(list);
  acct = purple_connection_get_account(gc);

  pd = gc->proto_data;
  idle = aware->status.time;
  stat = aware->status.status;
  id = aware->id.user;

  if(idle) {
    guint32 idle_len;       /*< how long a client has been idle */
    guint32 ugly_idle_len;  /*< how long a broken client has been idle */

    DEBUG_INFO("%s has idle value 0x%x\n", NSTR(id), idle);

    idle_len = time(NULL) - idle;
    ugly_idle_len = ((time(NULL) * 1000) - idle) / 1000;

	if(idle > ugly_idle_len)
		ugly_idle_len = 0;
	else
		ugly_idle_len = (ugly_idle_len - idle) / 1000;

    /*
       what's the deal here? Well, good clients are smart enough to
       publish their idle time by using an attribute to indicate that
       they went idle at some time UTC, in seconds since epoch. Bad
       clients use milliseconds since epoch. So we're going to compute
       the idle time for either method, then figure out the lower of
       the two and use that. Blame the ST 7.5 development team for
       this.
     */

    DEBUG_INFO("idle time: %u, ugly idle time: %u\n", idle_len, ugly_idle_len);

#if 1
    if(idle_len <= ugly_idle_len) {
      ; /* DEBUG_INFO("sane idle value, let's use it\n"); */
    } else {
      idle = time(NULL) - ugly_idle_len;
    }

#else
    if(idle < 0 || idle > time(NULL)) {
      DEBUG_INFO("hiding a messy idle value 0x%x\n", NSTR(id), idle);
      idle = -1;
    }
#endif
  }

  switch(stat) {
  case mwStatus_ACTIVE:
    status = MW_STATE_ACTIVE;
    idle = 0;
    break;

  case mwStatus_IDLE:
    if(! idle) idle = -1;
    break;

  case mwStatus_AWAY:
    status = MW_STATE_AWAY;
    break;

  case mwStatus_BUSY:
    status = MW_STATE_BUSY;
    break;
  }

  /* NAB group members */
  if(aware->group) {
    PurpleGroup *group;
    PurpleBuddy *buddy;
    PurpleBlistNode *bnode;

    group = g_hash_table_lookup(pd->group_list_map, list);
    buddy = purple_find_buddy_in_group(acct, id, group);
    bnode = (PurpleBlistNode *) buddy;

    if(! buddy) {
      struct mwServiceResolve *srvc;
      GList *query;

      buddy = purple_buddy_new(acct, id, NULL);
      purple_blist_add_buddy(buddy, NULL, group, NULL);

      bnode = (PurpleBlistNode *) buddy;

      srvc = pd->srvc_resolve;
      query = g_list_append(NULL, (char *) id);

      mwServiceResolve_resolve(srvc, query, mwResolveFlag_USERS,
			       blist_resolve_alias_cb, buddy, NULL);
      g_list_free(query);
    }

    purple_blist_node_set_int(bnode, BUDDY_KEY_TYPE, mwSametimeUser_NORMAL);
  }

  if(aware->online) {
    purple_prpl_got_user_status(acct, id, status, NULL);
    purple_prpl_got_user_idle(acct, id, !!idle, (time_t) idle);

  } else {
    purple_prpl_got_user_status(acct, id, MW_STATE_OFFLINE, NULL);
  }
}


static void mw_aware_list_on_attrib(struct mwAwareList *list,
				    struct mwAwareIdBlock *id,
				    struct mwAwareAttribute *attrib) {

  ; /* nothing. We'll get attribute data as we need it */
}


static void mw_aware_list_clear(struct mwAwareList *list) {
  ; /* nothing for now */
}


static struct mwAwareListHandler mw_aware_list_handler = {
  mw_aware_list_on_aware,
  mw_aware_list_on_attrib,
  mw_aware_list_clear,
};


/** Ensures that an Aware List is associated with the given group, and
    returns that list. */
static struct mwAwareList *
list_ensure(struct mwPurplePluginData *pd, PurpleGroup *group) {

  struct mwAwareList *list;

  g_return_val_if_fail(pd != NULL, NULL);
  g_return_val_if_fail(group != NULL, NULL);

  list = g_hash_table_lookup(pd->group_list_map, group);
  if(! list) {
    list = mwAwareList_new(pd->srvc_aware, &mw_aware_list_handler);
    mwAwareList_setClientData(list, pd->gc, NULL);

    mwAwareList_watchAttributes(list,
				mwAttribute_AV_PREFS_SET,
				mwAttribute_MICROPHONE,
				mwAttribute_SPEAKERS,
				mwAttribute_VIDEO_CAMERA,
				mwAttribute_FILE_TRANSFER,
				NULL);

    g_hash_table_replace(pd->group_list_map, group, list);
    g_hash_table_insert(pd->group_list_map, list, group);
  }

  return list;
}


static void blist_export(PurpleConnection *gc, struct mwSametimeList *stlist) {
  /* - find the account for this connection
     - iterate through the buddy list
     - add each buddy matching this account to the stlist
  */

  PurpleAccount *acct;
  PurpleBlistNode *gn, *cn, *bn;
  PurpleGroup *grp;
  PurpleBuddy *bdy;

  struct mwSametimeGroup *stg = NULL;
  struct mwIdBlock idb = { NULL, NULL };

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  for(gn = purple_blist_get_root(); gn;
		  gn = purple_blist_node_get_sibling_next(gn)) {
    const char *owner;
    const char *gname;
    enum mwSametimeGroupType gtype;
    gboolean gopen;

    if(! PURPLE_BLIST_NODE_IS_GROUP(gn)) continue;
    grp = (PurpleGroup *) gn;

    /* the group's type (normal or dynamic) */
    gtype = purple_blist_node_get_int(gn, GROUP_KEY_TYPE);
    if(! gtype) gtype = mwSametimeGroup_NORMAL;

    /* if it's a normal group with none of our people in it, skip it */
    if(gtype == mwSametimeGroup_NORMAL && !purple_group_on_account(grp, acct))
      continue;

    /* if the group has an owner and we're not it, skip it */
    owner = purple_blist_node_get_string(gn, GROUP_KEY_OWNER);
    if(owner && strcmp(owner, purple_account_get_username(acct)))
      continue;

    /* the group's actual name may be different from the purple group's
       name. Find whichever is there */
    gname = purple_blist_node_get_string(gn, GROUP_KEY_NAME);
    if(! gname) gname = purple_group_get_name(grp);

    /* we save this, but never actually honor it */
    gopen = ! purple_blist_node_get_bool(gn, GROUP_KEY_COLLAPSED);

    stg = mwSametimeGroup_new(stlist, gtype, gname);
    mwSametimeGroup_setAlias(stg, purple_group_get_name(grp));
    mwSametimeGroup_setOpen(stg, gopen);

    /* don't attempt to put buddies in a dynamic group, it breaks
       other clients */
    if(gtype == mwSametimeGroup_DYNAMIC)
      continue;

    for(cn = purple_blist_node_get_first_child(gn);
			cn;
			cn = purple_blist_node_get_sibling_next(cn)) {
      if(! PURPLE_BLIST_NODE_IS_CONTACT(cn)) continue;

      for(bn = purple_blist_node_get_first_child(cn);
			  bn;
			  bn = purple_blist_node_get_sibling_next(bn)) {
	if(! PURPLE_BLIST_NODE_IS_BUDDY(bn)) continue;
	if(! PURPLE_BLIST_NODE_SHOULD_SAVE(bn)) continue;

	bdy = (PurpleBuddy *) bn;

	if(purple_buddy_get_account(bdy) == acct) {
	  struct mwSametimeUser *stu;
	  enum mwSametimeUserType utype;

	  idb.user = (char *)purple_buddy_get_name(bdy);

	  utype = purple_blist_node_get_int(bn, BUDDY_KEY_TYPE);
	  if(! utype) utype = mwSametimeUser_NORMAL;

	  stu = mwSametimeUser_new(stg, utype, &idb);
	  mwSametimeUser_setShortName(stu, purple_buddy_get_server_alias(bdy));
	  mwSametimeUser_setAlias(stu, purple_buddy_get_local_buddy_alias(bdy));
	}
      }
    }
  }
}


static void blist_store(struct mwPurplePluginData *pd) {

  struct mwSametimeList *stlist;
  struct mwServiceStorage *srvc;
  struct mwStorageUnit *unit;

  PurpleConnection *gc;

  struct mwPutBuffer *b;
  struct mwOpaque *o;

  g_return_if_fail(pd != NULL);

  srvc = pd->srvc_store;
  g_return_if_fail(srvc != NULL);

  gc = pd->gc;

  if(BLIST_PREF_IS_LOCAL() || BLIST_PREF_IS_MERGE()) {
    DEBUG_INFO("preferences indicate not to save remote blist\n");
    return;

  } else if(MW_SERVICE_IS_DEAD(srvc)) {
    DEBUG_INFO("aborting save of blist: storage service is not alive\n");
    return;

  } else if(BLIST_PREF_IS_STORE() || BLIST_PREF_IS_SYNCH()) {
    DEBUG_INFO("saving remote blist\n");

  } else {
    g_return_if_reached();
  }

  /* create and export to a list object */
  stlist = mwSametimeList_new();
  blist_export(gc, stlist);

  /* write it to a buffer */
  b = mwPutBuffer_new();
  mwSametimeList_put(b, stlist);
  mwSametimeList_free(stlist);

  /* put the buffer contents into a storage unit */
  unit = mwStorageUnit_new(mwStore_AWARE_LIST);
  o = mwStorageUnit_asOpaque(unit);
  mwPutBuffer_finalize(o, b);

  /* save the storage unit to the service */
  mwServiceStorage_save(srvc, unit, NULL, NULL, NULL);
}


static gboolean blist_save_cb(gpointer data) {
  struct mwPurplePluginData *pd = data;

  blist_store(pd);
  pd->save_event = 0;
  return FALSE;
}


/** schedules the buddy list to be saved to the server */
static void blist_schedule(struct mwPurplePluginData *pd) {
  if(pd->save_event) return;

  pd->save_event = purple_timeout_add_seconds(BLIST_SAVE_SECONDS,
				    blist_save_cb, pd);
}


static gboolean buddy_is_external(PurpleBuddy *b) {
  g_return_val_if_fail(b != NULL, FALSE);
  return purple_str_has_prefix(purple_buddy_get_name(b), "@E ");
}


/** Actually add a buddy to the aware service, and schedule the buddy
    list to be saved to the server */
static void buddy_add(struct mwPurplePluginData *pd,
		      PurpleBuddy *buddy) {

  struct mwAwareIdBlock idb = { mwAware_USER, (char *) purple_buddy_get_name(buddy), NULL };
  struct mwAwareList *list;

  PurpleGroup *group;
  GList *add;

  add = g_list_prepend(NULL, &idb);

  group = purple_buddy_get_group(buddy);
  list = list_ensure(pd, group);

  if(mwAwareList_addAware(list, add)) {
    purple_blist_remove_buddy(buddy);
  }

  blist_schedule(pd);

  g_list_free(add);
}


/** ensure that a PurpleBuddy exists in the group with data
    appropriately matching the st user entry from the st list */
static PurpleBuddy *buddy_ensure(PurpleConnection *gc, PurpleGroup *group,
			       struct mwSametimeUser *stuser) {

  struct mwPurplePluginData *pd = gc->proto_data;
  PurpleBuddy *buddy;
  PurpleAccount *acct = purple_connection_get_account(gc);

  const char *id = mwSametimeUser_getUser(stuser);
  const char *name = mwSametimeUser_getShortName(stuser);
  const char *alias = mwSametimeUser_getAlias(stuser);
  enum mwSametimeUserType type = mwSametimeUser_getType(stuser);

  g_return_val_if_fail(id != NULL, NULL);
  g_return_val_if_fail(strlen(id) > 0, NULL);

  buddy = purple_find_buddy_in_group(acct, id, group);
  if(! buddy) {
    buddy = purple_buddy_new(acct, id, alias);

    purple_blist_add_buddy(buddy, NULL, group, NULL);
    buddy_add(pd, buddy);
  }

  purple_blist_alias_buddy(buddy, alias);
  purple_blist_server_alias_buddy(buddy, name);
  purple_blist_node_set_string((PurpleBlistNode *) buddy, BUDDY_KEY_NAME, name);
  purple_blist_node_set_int((PurpleBlistNode *) buddy, BUDDY_KEY_TYPE, type);

  return buddy;
}


/** add aware watch for a dynamic group */
static void group_add(struct mwPurplePluginData *pd,
		      PurpleGroup *group) {

  struct mwAwareIdBlock idb = { mwAware_GROUP, NULL, NULL };
  struct mwAwareList *list;
  const char *n;
  GList *add;

  n = purple_blist_node_get_string((PurpleBlistNode *) group, GROUP_KEY_NAME);
  if(! n) n = purple_group_get_name(group);

  idb.user = (char *) n;
  add = g_list_prepend(NULL, &idb);

  list = list_ensure(pd, group);
  mwAwareList_addAware(list, add);
  g_list_free(add);
}


/** ensure that a PurpleGroup exists in the blist with data
    appropriately matching the st group entry from the st list */
static PurpleGroup *group_ensure(PurpleConnection *gc,
			       struct mwSametimeGroup *stgroup) {
  PurpleAccount *acct;
  PurpleGroup *group = NULL;
  PurpleBuddyList *blist;
  PurpleBlistNode *gn;
  const char *name, *alias, *owner;
  enum mwSametimeGroupType type;

  acct = purple_connection_get_account(gc);
  owner = purple_account_get_username(acct);

  blist = purple_get_blist();
  g_return_val_if_fail(blist != NULL, NULL);

  name = mwSametimeGroup_getName(stgroup);
  alias = mwSametimeGroup_getAlias(stgroup);
  type = mwSametimeGroup_getType(stgroup);

  if (!name) {
    DEBUG_WARN("Can't ensure a null group\n");
    return NULL;
  }

  if (!name) {
    DEBUG_WARN("Can't ensure a null group\n");
    return NULL;
  }

  DEBUG_INFO("attempting to ensure group %s, called %s\n",
	     NSTR(name), NSTR(alias));

  /* first attempt at finding the group, by the name key */
  for(gn = purple_blist_get_root(); gn;
		  gn = purple_blist_node_get_sibling_next(gn)) {
    const char *n, *o;
    if(! PURPLE_BLIST_NODE_IS_GROUP(gn)) continue;
    n = purple_blist_node_get_string(gn, GROUP_KEY_NAME);
    o = purple_blist_node_get_string(gn, GROUP_KEY_OWNER);

    DEBUG_INFO("found group named %s, owned by %s\n", NSTR(n), NSTR(o));

    if(n && !strcmp(n, name)) {
      if(!o || !strcmp(o, owner)) {
	DEBUG_INFO("that'll work\n");
	group = (PurpleGroup *) gn;
	break;
      }
    }
  }

  /* try again, by alias */
  if(! group) {
    DEBUG_INFO("searching for group by alias %s\n", NSTR(alias));
    group = purple_find_group(alias);
  }

  /* oh well, no such group. Let's create it! */
  if(! group) {
    DEBUG_INFO("creating group\n");
    group = purple_group_new(alias);
    purple_blist_add_group(group, NULL);
  }

  gn = (PurpleBlistNode *) group;
  purple_blist_node_set_string(gn, GROUP_KEY_NAME, name);
  purple_blist_node_set_int(gn, GROUP_KEY_TYPE, type);

  if(type == mwSametimeGroup_DYNAMIC) {
    purple_blist_node_set_string(gn, GROUP_KEY_OWNER, owner);
    group_add(gc->proto_data, group);
  }

  return group;
}


/** merge the entries from a st list into the purple blist */
static void blist_merge(PurpleConnection *gc, struct mwSametimeList *stlist) {
  struct mwSametimeGroup *stgroup;
  struct mwSametimeUser *stuser;

  PurpleGroup *group;

  GList *gl, *gtl, *ul, *utl;

  gl = gtl = mwSametimeList_getGroups(stlist);
  for(; gl; gl = gl->next) {

    stgroup = (struct mwSametimeGroup *) gl->data;
    group = group_ensure(gc, stgroup);

    ul = utl = mwSametimeGroup_getUsers(stgroup);
    for(; ul; ul = ul->next) {

      stuser = (struct mwSametimeUser *) ul->data;
      buddy_ensure(gc, group, stuser);
    }
    g_list_free(utl);
  }
  g_list_free(gtl);
}


/** remove all buddies on account from group. If del is TRUE and group
    is left empty, remove group as well */
static void group_clear(PurpleGroup *group, PurpleAccount *acct, gboolean del) {
  PurpleConnection *gc;
  GList *prune = NULL;
  PurpleBlistNode *gn, *cn, *bn;

  g_return_if_fail(group != NULL);

  DEBUG_INFO("clearing members from pruned group %s\n", NSTR(purple_group_get_name(group)));

  gc = purple_account_get_connection(acct);
  g_return_if_fail(gc != NULL);

  gn = (PurpleBlistNode *) group;

  for(cn = purple_blist_node_get_first_child(gn);
		  cn;
		  cn = purple_blist_node_get_sibling_next(cn)) {
    if(! PURPLE_BLIST_NODE_IS_CONTACT(cn)) continue;

    for(bn = purple_blist_node_get_first_child(cn);
			bn;
			bn = purple_blist_node_get_sibling_next(bn)) {
      PurpleBuddy *gb = (PurpleBuddy *) bn;

      if(! PURPLE_BLIST_NODE_IS_BUDDY(bn)) continue;

      if(purple_buddy_get_account(gb) == acct) {
	DEBUG_INFO("clearing %s from group\n", NSTR(purple_buddy_get_name(gb)));
	prune = g_list_prepend(prune, gb);
      }
    }
  }

  /* quickly unsubscribe from presence for the entire group */
  purple_account_remove_group(acct, group);

  /* remove blist entries that need to go */
  while(prune) {
    purple_blist_remove_buddy(prune->data);
    prune = g_list_delete_link(prune, prune);
  }
  DEBUG_INFO("cleared buddies\n");

  /* optionally remove group from blist */
  if(del && !purple_blist_get_group_size(group, TRUE)) {
    DEBUG_INFO("removing empty group\n");
    purple_blist_remove_group(group);
  }
}


/** prune out group members that shouldn't be there */
static void group_prune(PurpleConnection *gc, PurpleGroup *group,
			struct mwSametimeGroup *stgroup) {

  PurpleAccount *acct;
  PurpleBlistNode *gn, *cn, *bn;

  GHashTable *stusers;
  GList *prune = NULL;
  GList *ul, *utl;

  g_return_if_fail(group != NULL);

  DEBUG_INFO("pruning membership of group %s\n", NSTR(purple_group_get_name(group)));

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  stusers = g_hash_table_new(g_str_hash, g_str_equal);

  /* build a hash table for quick lookup while pruning the group
     contents */
  utl = mwSametimeGroup_getUsers(stgroup);
  for(ul = utl; ul; ul = ul->next) {
    const char *id = mwSametimeUser_getUser(ul->data);
    g_hash_table_insert(stusers, (char *) id, ul->data);
    DEBUG_INFO("server copy has %s\n", NSTR(id));
  }
  g_list_free(utl);

  gn = (PurpleBlistNode *) group;

  for(cn = purple_blist_node_get_first_child(gn);
		  cn;
		  cn = purple_blist_node_get_sibling_next(cn)) {
    if(! PURPLE_BLIST_NODE_IS_CONTACT(cn)) continue;

    for(bn = purple_blist_node_get_first_child(cn);
			bn;
			bn = purple_blist_node_get_sibling_next(bn)) {
      PurpleBuddy *gb = (PurpleBuddy *) bn;

      if(! PURPLE_BLIST_NODE_IS_BUDDY(bn)) continue;

      /* if the account is correct and they're not in our table, mark
	 them for pruning */
      if(purple_buddy_get_account(gb) == acct && !g_hash_table_lookup(stusers, purple_buddy_get_name(gb))) {
	DEBUG_INFO("marking %s for pruning\n", NSTR(purple_buddy_get_name(gb)));
	prune = g_list_prepend(prune, gb);
      }
    }
  }
  DEBUG_INFO("done marking\n");

  g_hash_table_destroy(stusers);

  if(prune) {
    purple_account_remove_buddies(acct, prune, NULL);
    while(prune) {
      purple_blist_remove_buddy(prune->data);
      prune = g_list_delete_link(prune, prune);
    }
  }
}


/** synch the entries from a st list into the purple blist, removing any
    existing buddies that aren't in the st list */
static void blist_sync(PurpleConnection *gc, struct mwSametimeList *stlist) {

  PurpleAccount *acct;
  PurpleBuddyList *blist;
  PurpleBlistNode *gn;

  GHashTable *stgroups;
  GList *g_prune = NULL;

  GList *gl, *gtl;

  const char *acct_n;

  DEBUG_INFO("synchronizing local buddy list from server list\n");

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  acct_n = purple_account_get_username(acct);

  blist = purple_get_blist();
  g_return_if_fail(blist != NULL);

  /* build a hash table for quick lookup while pruning the local
     list, mapping group name to group structure */
  stgroups = g_hash_table_new(g_str_hash, g_str_equal);

  gtl = mwSametimeList_getGroups(stlist);
  for(gl = gtl; gl; gl = gl->next) {
    const char *name = mwSametimeGroup_getName(gl->data);
    g_hash_table_insert(stgroups, (char *) name, gl->data);
  }
  g_list_free(gtl);

  /* find all groups which should be pruned from the local list */
  for(gn = purple_blist_get_root(); gn;
		  gn = purple_blist_node_get_sibling_next(gn)) {
    PurpleGroup *grp = (PurpleGroup *) gn;
    const char *gname, *owner;
    struct mwSametimeGroup *stgrp;

    if(! PURPLE_BLIST_NODE_IS_GROUP(gn)) continue;

    /* group not belonging to this account */
    if(! purple_group_on_account(grp, acct))
      continue;

    /* dynamic group belonging to this account. don't prune contents */
    owner = purple_blist_node_get_string(gn, GROUP_KEY_OWNER);
    if(owner && !strcmp(owner, acct_n))
       continue;

    /* we actually are synching by this key as opposed to the group
       title, which can be different things in the st list */
    gname = purple_blist_node_get_string(gn, GROUP_KEY_NAME);
    if(! gname) gname = purple_group_get_name(grp);

    stgrp = g_hash_table_lookup(stgroups, gname);
    if(! stgrp) {
      /* remove the whole group */
      DEBUG_INFO("marking group %s for pruning\n", purple_group_get_name(grp));
      g_prune = g_list_prepend(g_prune, grp);

    } else {
      /* synch the group contents */
      group_prune(gc, grp, stgrp);
    }
  }
  DEBUG_INFO("done marking groups\n");

  /* don't need this anymore */
  g_hash_table_destroy(stgroups);

  /* prune all marked groups */
  while(g_prune) {
    PurpleGroup *grp = g_prune->data;
    PurpleBlistNode *gn = (PurpleBlistNode *) grp;
    const char *owner;
    gboolean del = TRUE;

    owner = purple_blist_node_get_string(gn, GROUP_KEY_OWNER);
    if(owner && strcmp(owner, acct_n)) {
      /* it's a specialty group belonging to another account with some
	 of our members in it, so don't fully delete it */
      del = FALSE;
    }

    group_clear(g_prune->data, acct, del);
    g_prune = g_list_delete_link(g_prune, g_prune);
  }

  /* done with the pruning, let's merge in the additions */
  blist_merge(gc, stlist);
}


/** callback passed to the storage service when it's told to load the
    st list */
static void fetch_blist_cb(struct mwServiceStorage *srvc,
			   guint32 result, struct mwStorageUnit *item,
			   gpointer data) {

  struct mwPurplePluginData *pd = data;
  struct mwSametimeList *stlist;

  struct mwGetBuffer *b;

  g_return_if_fail(result == ERR_SUCCESS);

  /* check our preferences for loading */
  if(BLIST_PREF_IS_LOCAL()) {
    DEBUG_INFO("preferences indicate not to load remote buddy list\n");
    return;
  }

  b = mwGetBuffer_wrap(mwStorageUnit_asOpaque(item));

  stlist = mwSametimeList_new();
  mwSametimeList_get(b, stlist);

  /* merge or synch depending on preferences */
  if(BLIST_PREF_IS_MERGE() || BLIST_PREF_IS_STORE()) {
    blist_merge(pd->gc, stlist);

  } else if(BLIST_PREF_IS_SYNCH()) {
    blist_sync(pd->gc, stlist);
  }

  mwSametimeList_free(stlist);
  mwGetBuffer_free(b);
}


/** signal triggered when a conversation is opened in Purple */
static void conversation_created_cb(PurpleConversation *g_conv,
				    struct mwPurplePluginData *pd) {

  /* we need to tell the IM service to negotiate features for the
     conversation right away, otherwise it'll wait until the first
     message is sent before offering NotesBuddy features. Therefore
     whenever Purple creates a conversation, we'll immediately open the
     channel to the other side and figure out what the target can
     handle. Unfortunately, this makes us vulnerable to Psychic Mode,
     whereas a more lazy negotiation based on the first message
     would not */

  PurpleConnection *gc;
  struct mwIdBlock who = { 0, 0 };
  struct mwConversation *conv;

  gc = purple_conversation_get_gc(g_conv);
  if(pd->gc != gc)
    return; /* not ours */

  if(purple_conversation_get_type(g_conv) != PURPLE_CONV_TYPE_IM)
    return; /* wrong type */

  who.user = (char *) purple_conversation_get_name(g_conv);
  conv = mwServiceIm_getConversation(pd->srvc_im, &who);

  convo_features(conv);

  if(mwConversation_isClosed(conv))
    mwConversation_open(conv);
}


static void blist_menu_nab(PurpleBlistNode *node, gpointer data) {
  struct mwPurplePluginData *pd = data;
  PurpleConnection *gc;

  PurpleGroup *group = (PurpleGroup *) node;

  GString *str;
  char *tmp;
  const char *gname;

  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  g_return_if_fail(gc != NULL);

  g_return_if_fail(PURPLE_BLIST_NODE_IS_GROUP(node));

  str = g_string_new(NULL);

  tmp = (char *) purple_blist_node_get_string(node, GROUP_KEY_NAME);
  gname = purple_group_get_name(group);

  g_string_append_printf(str, _("<b>Group Title:</b> %s<br>"), gname);
  g_string_append_printf(str, _("<b>Notes Group ID:</b> %s<br>"), tmp);

  tmp = g_strdup_printf(_("Info for Group %s"), gname);

  purple_notify_formatted(gc, tmp, _("Notes Address Book Information"),
			NULL, str->str, NULL, NULL);

  g_free(tmp);
  g_string_free(str, TRUE);
}


/** The normal blist menu prpl function doesn't get called for groups,
    so we use the blist-node-extended-menu signal to trigger this
    handler */
static void blist_node_menu_cb(PurpleBlistNode *node,
                               GList **menu, struct mwPurplePluginData *pd) {
  const char *owner;
  PurpleGroup *group;
  PurpleAccount *acct;
  PurpleMenuAction *act;

  /* we only want groups */
  if(! PURPLE_BLIST_NODE_IS_GROUP(node)) return;
  group = (PurpleGroup *) node;

  acct = purple_connection_get_account(pd->gc);
  g_return_if_fail(acct != NULL);

  /* better make sure we're connected */
  if(! purple_account_is_connected(acct)) return;

#if 0
  /* if there's anyone in the group for this acct, offer to invite
     them all to a conference */
  if(purple_group_on_account(group, acct)) {
    act = purple_menu_action_new(_("Invite Group to Conference..."),
                               PURPLE_CALLBACK(blist_menu_group_invite),
                               pd, NULL);
    *menu = g_list_append(*menu, NULL);
  }
#endif

  /* check if it's a NAB group for this account */
  owner = purple_blist_node_get_string(node, GROUP_KEY_OWNER);
  if(owner && !strcmp(owner, purple_account_get_username(acct))) {
    act = purple_menu_action_new(_("Get Notes Address Book Info"),
                               PURPLE_CALLBACK(blist_menu_nab), pd, NULL);
    *menu = g_list_append(*menu, act);
  }
}


/* lifted this from oldstatus, since HEAD doesn't do this at login
   anymore. */
static void blist_init(PurpleAccount *acct) {
  PurpleBlistNode *gnode, *cnode, *bnode;
  GList *add_buds = NULL;

  for(gnode = purple_blist_get_root(); gnode;
		  gnode = purple_blist_node_get_sibling_next(gnode)) {
    if(! PURPLE_BLIST_NODE_IS_GROUP(gnode)) continue;

    for(cnode = purple_blist_node_get_first_child(gnode);
			cnode;
			cnode = purple_blist_node_get_sibling_next(cnode)) {
      if(! PURPLE_BLIST_NODE_IS_CONTACT(cnode))
	continue;
      for(bnode = purple_blist_node_get_first_child(cnode);
			  bnode;
			  bnode = purple_blist_node_get_sibling_next(bnode)) {
	PurpleBuddy *b;
	if(!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
	  continue;

	b = (PurpleBuddy *)bnode;
	if(purple_buddy_get_account(b) == acct) {
	  add_buds = g_list_append(add_buds, b);
	}
      }
    }
  }

  if(add_buds) {
    purple_account_add_buddies(acct, add_buds);
    g_list_free(add_buds);
  }
}


/** Last thing to happen from a started session */
static void services_starting(struct mwPurplePluginData *pd) {

  PurpleConnection *gc;
  PurpleAccount *acct;
  struct mwStorageUnit *unit;
  PurpleBlistNode *l;

  gc = pd->gc;
  acct = purple_connection_get_account(gc);

  /* grab the buddy list from the server */
  unit = mwStorageUnit_new(mwStore_AWARE_LIST);
  mwServiceStorage_load(pd->srvc_store, unit, fetch_blist_cb, pd, NULL);

  /* find all the NAB groups and subscribe to them */
  for(l = purple_blist_get_root(); l;
		  l = purple_blist_node_get_sibling_next(l)) {
    PurpleGroup *group = (PurpleGroup *) l;
    enum mwSametimeGroupType gt;
    const char *owner;

    if(! PURPLE_BLIST_NODE_IS_GROUP(l)) continue;

    /* if the group is ownerless, or has an owner and we're not it,
       skip it */
    owner = purple_blist_node_get_string(l, GROUP_KEY_OWNER);
    if(!owner || strcmp(owner, purple_account_get_username(acct)))
      continue;

    gt = purple_blist_node_get_int(l, GROUP_KEY_TYPE);
    if(gt == mwSametimeGroup_DYNAMIC)
      group_add(pd, group);
  }

  /* set the aware attributes */
  /* indicate we understand what AV prefs are, but don't support any */
  mwServiceAware_setAttributeBoolean(pd->srvc_aware,
				     mwAttribute_AV_PREFS_SET, TRUE);
  mwServiceAware_unsetAttribute(pd->srvc_aware, mwAttribute_MICROPHONE);
  mwServiceAware_unsetAttribute(pd->srvc_aware, mwAttribute_SPEAKERS);
  mwServiceAware_unsetAttribute(pd->srvc_aware, mwAttribute_VIDEO_CAMERA);

  /* ... but we can do file transfers! */
  mwServiceAware_setAttributeBoolean(pd->srvc_aware,
				     mwAttribute_FILE_TRANSFER, TRUE);

  blist_init(acct);
}


static void session_loginRedirect(struct mwSession *session,
				  const char *host) {
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleAccount *account;
  guint port;
  const char *current_host;

  pd = mwSession_getClientData(session);
  gc = pd->gc;
  account = purple_connection_get_account(gc);
  port = purple_account_get_int(account, MW_KEY_PORT, MW_PLUGIN_DEFAULT_PORT);
  current_host = purple_account_get_string(account, MW_KEY_HOST,
					 MW_PLUGIN_DEFAULT_HOST);

  if(purple_account_get_bool(account, MW_KEY_FORCE, FALSE) ||
     !host || (! strcmp(current_host, host)) ||
     (purple_proxy_connect(gc, account, host, port, connect_cb, pd) == NULL)) {

    /* if we're configured to force logins, or if we're being
       redirected to the already configured host, or if we couldn't
       connect to the new host, we'll force the login instead */

    mwSession_forceLogin(session);
  }
}


static void mw_prpl_set_status(PurpleAccount *acct, PurpleStatus *status);


/** called from mw_session_stateChange when the session's state is
    mwSession_STARTED. Any finalizing of start-up stuff should go
    here */
static void session_started(struct mwPurplePluginData *pd) {
  PurpleStatus *status;
  PurpleAccount *acct;

  /* set out initial status */
  acct = purple_connection_get_account(pd->gc);
  status = purple_account_get_active_status(acct);
  mw_prpl_set_status(acct, status);

  /* start watching for new conversations */
  purple_signal_connect(purple_conversations_get_handle(),
		      "conversation-created", pd,
		      PURPLE_CALLBACK(conversation_created_cb), pd);

  /* watch for group extended menu items */
  purple_signal_connect(purple_blist_get_handle(),
		      "blist-node-extended-menu", pd,
		      PURPLE_CALLBACK(blist_node_menu_cb), pd);

  /* use our services to do neat things */
  services_starting(pd);
}


static void session_stopping(struct mwPurplePluginData *pd) {
  /* stop watching the signals from session_started */
  purple_signals_disconnect_by_handle(pd);
}


static void mw_session_stateChange(struct mwSession *session,
				   enum mwSessionState state,
				   gpointer info) {
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  const char *msg = NULL;

  pd = mwSession_getClientData(session);
  gc = pd->gc;

  switch(state) {
  case mwSession_STARTING:
    msg = _("Sending Handshake");
    purple_connection_update_progress(gc, msg, 2, MW_CONNECT_STEPS);
    break;

  case mwSession_HANDSHAKE:
    msg = _("Waiting for Handshake Acknowledgement");
    purple_connection_update_progress(gc, msg, 3, MW_CONNECT_STEPS);
    break;

  case mwSession_HANDSHAKE_ACK:
    msg = _("Handshake Acknowledged, Sending Login");
    purple_connection_update_progress(gc, msg, 4, MW_CONNECT_STEPS);
    break;

  case mwSession_LOGIN:
    msg = _("Waiting for Login Acknowledgement");
    purple_connection_update_progress(gc, msg, 5, MW_CONNECT_STEPS);
    break;

  case mwSession_LOGIN_REDIR:
    msg = _("Login Redirected");
    purple_connection_update_progress(gc, msg, 6, MW_CONNECT_STEPS);
    session_loginRedirect(session, info);
    break;

  case mwSession_LOGIN_CONT:
    msg = _("Forcing Login");
    purple_connection_update_progress(gc, msg, 7, MW_CONNECT_STEPS);

  case mwSession_LOGIN_ACK:
    msg = _("Login Acknowledged");
    purple_connection_update_progress(gc, msg, 8, MW_CONNECT_STEPS);
    break;

  case mwSession_STARTED:
    msg = _("Starting Services");
    purple_connection_update_progress(gc, msg, 9, MW_CONNECT_STEPS);

    session_started(pd);

    msg = _("Connected");
    purple_connection_update_progress(gc, msg, 10, MW_CONNECT_STEPS);
    purple_connection_set_state(gc, PURPLE_CONNECTED);
    break;

  case mwSession_STOPPING:

    session_stopping(pd);

    if(GPOINTER_TO_UINT(info) & ERR_FAILURE) {
      char *err = mwError(GPOINTER_TO_UINT(info));
      PurpleConnectionError reason;
      switch (GPOINTER_TO_UINT(info)) {
      case VERSION_MISMATCH:
        reason = PURPLE_CONNECTION_ERROR_OTHER_ERROR;
        break;

      case USER_RESTRICTED:
      case INCORRECT_LOGIN:
      case USER_UNREGISTERED:
      case GUEST_IN_USE:
        reason = PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED;
        break;

      case ENCRYPT_MISMATCH:
      case ERR_ENCRYPT_NO_SUPPORT:
      case ERR_NO_COMMON_ENCRYPT:
        reason = PURPLE_CONNECTION_ERROR_ENCRYPTION_ERROR;
        break;

      case VERIFICATION_DOWN:
        reason = PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE;
        break;

      case MULTI_SERVER_LOGIN:
      case MULTI_SERVER_LOGIN2:
        reason = PURPLE_CONNECTION_ERROR_NAME_IN_USE;
        break;

      default:
        reason = PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
      }
      purple_connection_error_reason(gc, reason, err);
      g_free(err);
    }
    break;

  case mwSession_STOPPED:
    break;

  case mwSession_UNKNOWN:
  default:
    DEBUG_WARN("session in unknown state\n");
  }
}


static void mw_session_setPrivacyInfo(struct mwSession *session) {
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleAccount *acct;
  struct mwPrivacyInfo *privacy;
  GSList *l, **ll;
  guint count;

  DEBUG_INFO("privacy information set from server\n");

  g_return_if_fail(session != NULL);

  pd = mwSession_getClientData(session);
  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  g_return_if_fail(gc != NULL);

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  privacy = mwSession_getPrivacyInfo(session);
  count = privacy->count;

  ll = (privacy->deny)? &acct->deny: &acct->permit;
  for(l = *ll; l; l = l->next) g_free(l->data);
  g_slist_free(*ll);
  l = *ll = NULL;

  while(count--) {
    struct mwUserItem *u = privacy->users + count;
    l = g_slist_prepend(l, g_strdup(u->id));
  }
  *ll = l;
}


static void mw_session_setUserStatus(struct mwSession *session) {
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  struct mwAwareIdBlock idb = { mwAware_USER, NULL, NULL };
  struct mwUserStatus *stat;

  g_return_if_fail(session != NULL);

  pd = mwSession_getClientData(session);
  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  g_return_if_fail(gc != NULL);

  idb.user = mwSession_getProperty(session, mwSession_AUTH_USER_ID);
  stat = mwSession_getUserStatus(session);

  /* trigger an update of our own status if we're in the buddy list */
  mwServiceAware_setStatus(pd->srvc_aware, &idb, stat);
}


static void mw_session_admin(struct mwSession *session,
			     const char *text) {
  PurpleConnection *gc;
  PurpleAccount *acct;
  const char *host;
  const char *msg;
  char *prim;

  gc = session_to_gc(session);
  g_return_if_fail(gc != NULL);

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  host = purple_account_get_string(acct, MW_KEY_HOST, NULL);

  msg = _("A Sametime administrator has issued the following announcement"
	   " on server %s");
  prim = g_strdup_printf(msg, NSTR(host));

  purple_notify_message(gc, PURPLE_NOTIFY_MSG_INFO,
		      _("Sametime Administrator Announcement"),
		      prim, text, NULL, NULL);

  g_free(prim);
}


/** called from read_cb, attempts to read available data from sock and
    pass it to the session, passing back the return code from the read
    call for handling in read_cb */
static int read_recv(struct mwSession *session, int sock) {
  guchar buf[BUF_LEN];
  int len;

  len = read(sock, buf, BUF_LEN);
  if(len > 0) {
    mwSession_recv(session, buf, len);
  }

  return len;
}


/** callback triggered from purple_input_add, watches the socked for
    available data to be processed by the session */
static void read_cb(gpointer data, gint source, PurpleInputCondition cond) {
  struct mwPurplePluginData *pd = data;
  int ret = 0, err = 0;

  g_return_if_fail(pd != NULL);

  ret = read_recv(pd->session, pd->socket);

  /* normal operation ends here */
  if(ret > 0) return;

  /* fetch the global error value */
  err = errno;

  /* read problem occurred if we're here, so we'll need to take care of
     it and clean up internal state */

  if(pd->socket) {
    close(pd->socket);
    pd->socket = 0;
  }

  if(pd->gc->inpa) {
    purple_input_remove(pd->gc->inpa);
    pd->gc->inpa = 0;
  }

  if(! ret) {
    DEBUG_INFO("connection reset\n");
    purple_connection_error_reason(pd->gc,
                                   PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                   _("Server closed the connection"));

  } else if(ret < 0) {
    const gchar *err_str = g_strerror(err);
    char *msg = NULL;

    DEBUG_INFO("error in read callback: %s\n", err_str);

    msg = g_strdup_printf(_("Lost connection with server: %s"), err_str);
    purple_connection_error_reason(pd->gc,
                                   PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                   msg);
    g_free(msg);
  }
}


/** Callback passed to purple_proxy_connect when an account is logged
    in, and if the session logging in receives a redirect message */
static void connect_cb(gpointer data, gint source, const gchar *error_message) {

  struct mwPurplePluginData *pd = data;
  PurpleConnection *gc = pd->gc;

  if(source < 0) {
    /* connection failed */

    if(pd->socket) {
      /* this is a redirect connect, force login on existing socket */
      mwSession_forceLogin(pd->session);

    } else {
      /* this is a regular connect, error out */
      gchar *tmp = g_strdup_printf(_("Unable to connect: %s"),
          error_message);
      purple_connection_error_reason(pd->gc,
                                     PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                     tmp);
      g_free(tmp);
    }

    return;
  }

  if(pd->socket) {
    /* stop any existing login attempt */
    mwSession_stop(pd->session, ERR_SUCCESS);
  }

  pd->socket = source;
  gc->inpa = purple_input_add(source, PURPLE_INPUT_READ,
			    read_cb, pd);

  mwSession_start(pd->session);
}


static void mw_session_announce(struct mwSession *s,
				struct mwLoginInfo *from,
				gboolean may_reply,
				const char *text) {
  struct mwPurplePluginData *pd;
  PurpleAccount *acct;
  PurpleConversation *conv;
  PurpleBuddy *buddy;
  char *who = from->user_id;
  char *msg;

  pd = mwSession_getClientData(s);
  acct = purple_connection_get_account(pd->gc);
  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, who, acct);
  if(! conv) conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, who);

  buddy = purple_find_buddy(acct, who);
  if(buddy) who = (char *) purple_buddy_get_contact_alias(buddy);

  who = g_strdup_printf(_("Announcement from %s"), who);
  msg = purple_markup_linkify(text);

  purple_conversation_write(conv, who, msg ? msg : "", PURPLE_MESSAGE_RECV, time(NULL));
  g_free(who);
  g_free(msg);
}


static struct mwSessionHandler mw_session_handler = {
  mw_session_io_write,
  mw_session_io_close,
  mw_session_clear,
  mw_session_stateChange,
  mw_session_setPrivacyInfo,
  mw_session_setUserStatus,
  mw_session_admin,
  mw_session_announce,
};


static void mw_aware_on_attrib(struct mwServiceAware *srvc,
			       struct mwAwareAttribute *attrib) {

  ; /** @todo handle server attributes.  There may be some stuff we
	actually want to look for, but I'm not aware of anything right
	now.*/
}


static void mw_aware_clear(struct mwServiceAware *srvc) {
  ; /* nothing for now */
}


static struct mwAwareHandler mw_aware_handler = {
  mw_aware_on_attrib,
  mw_aware_clear,
};


static struct mwServiceAware *mw_srvc_aware_new(struct mwSession *s) {
  struct mwServiceAware *srvc;
  srvc = mwServiceAware_new(s, &mw_aware_handler);
  return srvc;
};


static void mw_conf_invited(struct mwConference *conf,
			    struct mwLoginInfo *inviter,
			    const char *invitation) {

  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;

  char *c_inviter, *c_name, *c_topic, *c_invitation;
  GHashTable *ht;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);

  c_inviter = g_strdup(inviter->user_id);
  g_hash_table_insert(ht, CHAT_KEY_CREATOR, c_inviter);

  c_name = g_strdup(mwConference_getName(conf));
  g_hash_table_insert(ht, CHAT_KEY_NAME, c_name);

  c_topic = g_strdup(mwConference_getTitle(conf));
  g_hash_table_insert(ht, CHAT_KEY_TOPIC, c_topic);

  c_invitation = g_strdup(invitation);
  g_hash_table_insert(ht, CHAT_KEY_INVITE, c_invitation);

  DEBUG_INFO("received invitation from '%s' to join ('%s','%s'): '%s'\n",
	     NSTR(c_inviter), NSTR(c_name),
	     NSTR(c_topic), NSTR(c_invitation));

  if(! c_topic) c_topic = "(no title)";
  if(! c_invitation) c_invitation = "(no message)";
  serv_got_chat_invite(gc, c_topic, c_inviter, c_invitation, ht);
}


/* The following mess helps us relate a mwConference to a PurpleConvChat
   in the various forms by which either may be indicated */

#define CONF_TO_ID(conf)   (GPOINTER_TO_INT(conf))
#define ID_TO_CONF(pd, id) (conf_find_by_id((pd), (id)))

#define CHAT_TO_ID(chat)   (purple_conv_chat_get_id(chat))
#define ID_TO_CHAT(id)     (purple_find_chat(id))

#define CHAT_TO_CONF(pd, chat)  (ID_TO_CONF((pd), CHAT_TO_ID(chat)))
#define CONF_TO_CHAT(conf)      (ID_TO_CHAT(CONF_TO_ID(conf)))


static struct mwConference *
conf_find_by_id(struct mwPurplePluginData *pd, int id) {

  struct mwServiceConference *srvc = pd->srvc_conf;
  struct mwConference *conf = NULL;
  GList *l, *ll;

  ll = mwServiceConference_getConferences(srvc);
  for(l = ll; l; l = l->next) {
    struct mwConference *c = l->data;
    PurpleConvChat *h = mwConference_getClientData(c);

    if(CHAT_TO_ID(h) == id) {
      conf = c;
      break;
    }
  }
  g_list_free(ll);

  return conf;
}


static void mw_conf_opened(struct mwConference *conf, GList *members) {
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConversation *g_conf;

  const char *n = mwConference_getName(conf);
  const char *t = mwConference_getTitle(conf);

  DEBUG_INFO("conf %s opened, %u initial members\n",
	     NSTR(n), g_list_length(members));

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  if(! t) t = "(no title)";
  g_conf = serv_got_joined_chat(gc, CONF_TO_ID(conf), t);

  mwConference_setClientData(conf, PURPLE_CONV_CHAT(g_conf), NULL);

  for(; members; members = members->next) {
    struct mwLoginInfo *peer = members->data;
    purple_conv_chat_add_user(PURPLE_CONV_CHAT(g_conf), peer->user_id,
			    NULL, PURPLE_CBFLAGS_NONE, FALSE);
  }
}


static void mw_conf_closed(struct mwConference *conf, guint32 reason) {
  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;

  const char *n = mwConference_getName(conf);
  char *msg = mwError(reason);

  DEBUG_INFO("conf %s closed, 0x%08x\n", NSTR(n), reason);

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  serv_got_chat_left(gc, CONF_TO_ID(conf));

  purple_notify_error(gc, _("Conference Closed"), NULL, msg);
  g_free(msg);
}


static void mw_conf_peer_joined(struct mwConference *conf,
				struct mwLoginInfo *peer) {

  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConvChat *g_conf;

  const char *n = mwConference_getName(conf);

  DEBUG_INFO("%s joined conf %s\n", NSTR(peer->user_id), NSTR(n));

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  g_conf = mwConference_getClientData(conf);
  g_return_if_fail(g_conf != NULL);

  purple_conv_chat_add_user(g_conf, peer->user_id,
			  NULL, PURPLE_CBFLAGS_NONE, TRUE);
}


static void mw_conf_peer_parted(struct mwConference *conf,
				struct mwLoginInfo *peer) {

  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConvChat *g_conf;

  const char *n = mwConference_getName(conf);

  DEBUG_INFO("%s left conf %s\n", NSTR(peer->user_id), NSTR(n));

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  g_conf = mwConference_getClientData(conf);
  g_return_if_fail(g_conf != NULL);

  purple_conv_chat_remove_user(g_conf, peer->user_id, NULL);
}


static void mw_conf_text(struct mwConference *conf,
			 struct mwLoginInfo *who, const char *text) {

  struct mwServiceConference *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  char *esc;

  if(! text) return;

  srvc = mwConference_getService(conf);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  esc = g_markup_escape_text(text, -1);
  serv_got_chat_in(gc, CONF_TO_ID(conf), who->user_id, 0, esc, time(NULL));
  g_free(esc);
}


static void mw_conf_typing(struct mwConference *conf,
			   struct mwLoginInfo *who, gboolean typing) {

  /* purple really has no good way to expose this to the user. */

  const char *n = mwConference_getName(conf);
  const char *w = who->user_id;

  if(typing) {
    DEBUG_INFO("%s in conf %s: <typing>\n", NSTR(w), NSTR(n));

  } else {
    DEBUG_INFO("%s in conf %s: <stopped typing>\n", NSTR(w), NSTR(n));
  }
}


static void mw_conf_clear(struct mwServiceConference *srvc) {
  ;
}


static struct mwConferenceHandler mw_conference_handler = {
  mw_conf_invited,
  mw_conf_opened,
  mw_conf_closed,
  mw_conf_peer_joined,
  mw_conf_peer_parted,
  mw_conf_text,
  mw_conf_typing,
  mw_conf_clear,
};


static struct mwServiceConference *mw_srvc_conf_new(struct mwSession *s) {
  struct mwServiceConference *srvc;
  srvc = mwServiceConference_new(s, &mw_conference_handler);
  return srvc;
}


/** size of an outgoing file transfer chunk */
#define MW_FT_LEN  (BUF_LONG * 2)


static void ft_incoming_cancel(PurpleXfer *xfer) {
  /* incoming transfer rejected or cancelled in-progress */
  struct mwFileTransfer *ft = xfer->data;
  if(ft) mwFileTransfer_reject(ft);
}


static void ft_incoming_init(PurpleXfer *xfer) {
  /* incoming transfer accepted */

  /* - accept the mwFileTransfer
     - open/create the local FILE "wb"
     - stick the FILE's fp in xfer->dest_fp
  */

  struct mwFileTransfer *ft;
  FILE *fp;

  ft = xfer->data;

  fp = g_fopen(xfer->local_filename, "wb");
  if(! fp) {
    mwFileTransfer_cancel(ft);
    return;
  }

  xfer->dest_fp = fp;
  mwFileTransfer_accept(ft);
}


static void mw_ft_offered(struct mwFileTransfer *ft) {
  /*
    - create a purple ft object
    - offer it
  */

  struct mwServiceFileTransfer *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleAccount *acct;
  const char *who;
  PurpleXfer *xfer;

  /* @todo add some safety checks */
  srvc = mwFileTransfer_getService(ft);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;
  acct = purple_connection_get_account(gc);

  who = mwFileTransfer_getUser(ft)->user;

  DEBUG_INFO("file transfer %p offered\n", ft);
  DEBUG_INFO(" from: %s\n", NSTR(who));
  DEBUG_INFO(" file: %s\n", NSTR(mwFileTransfer_getFileName(ft)));
  DEBUG_INFO(" size: %u\n", mwFileTransfer_getFileSize(ft));
  DEBUG_INFO(" text: %s\n", NSTR(mwFileTransfer_getMessage(ft)));

  xfer = purple_xfer_new(acct, PURPLE_XFER_RECEIVE, who);
  if (xfer)
  {
	purple_xfer_ref(xfer);
	mwFileTransfer_setClientData(ft, xfer, (GDestroyNotify) purple_xfer_unref);
	xfer->data = ft;

	purple_xfer_set_init_fnc(xfer, ft_incoming_init);
	purple_xfer_set_cancel_recv_fnc(xfer, ft_incoming_cancel);
	purple_xfer_set_request_denied_fnc(xfer, ft_incoming_cancel);

	purple_xfer_set_filename(xfer, mwFileTransfer_getFileName(ft));
	purple_xfer_set_size(xfer, mwFileTransfer_getFileSize(ft));
	purple_xfer_set_message(xfer, mwFileTransfer_getMessage(ft));

	purple_xfer_request(xfer);
  }
}


static void ft_send(struct mwFileTransfer *ft, FILE *fp) {
  guchar buf[MW_FT_LEN];
  struct mwOpaque o = { MW_FT_LEN, buf };
  guint32 rem;
  PurpleXfer *xfer;

  xfer = mwFileTransfer_getClientData(ft);

  rem = mwFileTransfer_getRemaining(ft);
  if(rem < MW_FT_LEN) o.len = rem;

  if(fread(buf, (size_t) o.len, 1, fp)) {

    /* calculate progress and display it */
    xfer->bytes_sent += o.len;
    xfer->bytes_remaining -= o.len;
    purple_xfer_update_progress(xfer);

    mwFileTransfer_send(ft, &o);

  } else {
    int err = errno;
    DEBUG_WARN("problem reading from file %s: %s\n",
	       NSTR(mwFileTransfer_getFileName(ft)), g_strerror(err));

    mwFileTransfer_cancel(ft);
  }
}


static void mw_ft_opened(struct mwFileTransfer *ft) {
  /*
    - get purple ft from client data in ft
    - set the state to active
  */

  PurpleXfer *xfer;

  xfer = mwFileTransfer_getClientData(ft);

  if(! xfer) {
    mwFileTransfer_cancel(ft);
    mwFileTransfer_free(ft);
    g_return_if_reached();
  }

  if(purple_xfer_get_type(xfer) == PURPLE_XFER_SEND) {
    xfer->dest_fp = g_fopen(xfer->local_filename, "rb");
    ft_send(ft, xfer->dest_fp);
  }
}


static void mw_ft_closed(struct mwFileTransfer *ft, guint32 code) {
  /*
    - get purple ft from client data in ft
    - indicate rejection/cancelation/completion
    - free the file transfer itself
  */

  PurpleXfer *xfer;

  xfer = mwFileTransfer_getClientData(ft);
  if(xfer) {
    xfer->data = NULL;

    if(! mwFileTransfer_getRemaining(ft)) {
      purple_xfer_set_completed(xfer, TRUE);
      purple_xfer_end(xfer);

    } else if(mwFileTransfer_isCancelLocal(ft)) {
      /* calling purple_xfer_cancel_local is redundant, since that's
	 probably what triggered this function to be called */
      ;

    } else if(mwFileTransfer_isCancelRemote(ft)) {
      /* steal the reference for the xfer */
      mwFileTransfer_setClientData(ft, NULL, NULL);
      purple_xfer_cancel_remote(xfer);

      /* drop the stolen reference */
      purple_xfer_unref(xfer);
      return;
    }
  }

  mwFileTransfer_free(ft);
}


static void mw_ft_recv(struct mwFileTransfer *ft,
		       struct mwOpaque *data) {
  /*
    - get purple ft from client data in ft
    - update transfered percentage
    - if done, destroy the ft, disassociate from purple ft
  */

  PurpleXfer *xfer;
  FILE *fp;
  size_t wc;

  xfer = mwFileTransfer_getClientData(ft);
  g_return_if_fail(xfer != NULL);

  fp = xfer->dest_fp;
  g_return_if_fail(fp != NULL);

  /* we must collect and save our precious data */
  wc = fwrite(data->data, 1, data->len, fp);
  if (wc != data->len) {
    DEBUG_ERROR("failed to write data\n");
    purple_xfer_cancel_local(xfer);
    return;
  }

  /* update the progress */
  xfer->bytes_sent += data->len;
  xfer->bytes_remaining -= data->len;
  purple_xfer_update_progress(xfer);

  /* let the other side know we got it, and to send some more */
  mwFileTransfer_ack(ft);
}


static void mw_ft_ack(struct mwFileTransfer *ft) {
  PurpleXfer *xfer;

  xfer = mwFileTransfer_getClientData(ft);
  g_return_if_fail(xfer != NULL);
  g_return_if_fail(xfer->watcher == 0);

  if(! mwFileTransfer_getRemaining(ft)) {
    purple_xfer_set_completed(xfer, TRUE);
    purple_xfer_end(xfer);

  } else if(mwFileTransfer_isOpen(ft)) {
    ft_send(ft, xfer->dest_fp);
  }
}


static void mw_ft_clear(struct mwServiceFileTransfer *srvc) {
  ;
}


static struct mwFileTransferHandler mw_ft_handler = {
  mw_ft_offered,
  mw_ft_opened,
  mw_ft_closed,
  mw_ft_recv,
  mw_ft_ack,
  mw_ft_clear,
};


static struct mwServiceFileTransfer *mw_srvc_ft_new(struct mwSession *s) {
  struct mwServiceFileTransfer *srvc;
  GHashTable *ft_map;

  ft_map = g_hash_table_new(g_direct_hash, g_direct_equal);

  srvc = mwServiceFileTransfer_new(s, &mw_ft_handler);
  mwService_setClientData(MW_SERVICE(srvc), ft_map,
			  (GDestroyNotify) g_hash_table_destroy);

  return srvc;
}


static void convo_data_free(struct convo_data *cd) {
  GList *l;

  /* clean the queue */
  for(l = cd->queue; l; l = g_list_delete_link(l, l)) {
    struct convo_msg *m = l->data;
    if(m->clear) m->clear(m->data);
    g_free(m);
  }

  g_free(cd);
}


/** allocates a convo_data structure and associates it with the
    conversation in the client data slot */
static void convo_data_new(struct mwConversation *conv) {
  struct convo_data *cd;

  g_return_if_fail(conv != NULL);

  if(mwConversation_getClientData(conv))
    return;

  cd = g_new0(struct convo_data, 1);
  cd->conv = conv;

  mwConversation_setClientData(conv, cd, (GDestroyNotify) convo_data_free);
}


static PurpleConversation *convo_get_gconv(struct mwConversation *conv) {
  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleAccount *acct;

  struct mwIdBlock *idb;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;
  acct = purple_connection_get_account(gc);

  idb = mwConversation_getTarget(conv);

  return purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
					     idb->user, acct);
}


static void convo_queue(struct mwConversation *conv,
			enum mwImSendType type, gconstpointer data) {

  struct convo_data *cd;
  struct convo_msg *m;

  convo_data_new(conv);
  cd = mwConversation_getClientData(conv);

  m = g_new0(struct convo_msg, 1);
  m->type = type;

  switch(type) {
  case mwImSend_PLAIN:
    m->data = g_strdup(data);
    m->clear = g_free;
    break;

  case mwImSend_TYPING:
  default:
    m->data = (gpointer) data;
    m->clear = NULL;
  }

  cd->queue = g_list_append(cd->queue, m);
}


/* Does what it takes to get an error displayed for a conversation */
static void convo_error(struct mwConversation *conv, guint32 err) {
  PurpleConversation *gconv;
  char *tmp, *text;
  struct mwIdBlock *idb;

  idb = mwConversation_getTarget(conv);

  tmp = mwError(err);
  text = g_strconcat(_("Unable to send message: "), tmp, NULL);

  gconv = convo_get_gconv(conv);
  if(gconv && !purple_conv_present_error(idb->user, gconv->account, text)) {

    g_free(text);
    text = g_strdup_printf(_("Unable to send message to %s:"),
			   (idb->user)? idb->user: "(unknown)");
    purple_notify_error(purple_account_get_connection(gconv->account),
		      NULL, text, tmp);
  }

  g_free(tmp);
  g_free(text);
}


static void convo_queue_send(struct mwConversation *conv) {
  struct convo_data *cd;
  GList *l;

  cd = mwConversation_getClientData(conv);

  for(l = cd->queue; l; l = g_list_delete_link(l, l)) {
    struct convo_msg *m = l->data;

    mwConversation_send(conv, m->type, m->data);

    if(m->clear) m->clear(m->data);
    g_free(m);
  }

  cd->queue = NULL;
}


/**  called when a mw conversation leaves a purple conversation to
     inform the purple conversation that it's unsafe to offer any *cool*
     features. */
static void convo_nofeatures(struct mwConversation *conv) {
  PurpleConversation *gconv;
  PurpleConnection *gc;

  gconv = convo_get_gconv(conv);
  if(! gconv) return;

  gc = purple_conversation_get_gc(gconv);
  if(! gc) return;

  purple_conversation_set_features(gconv, gc->flags);
}


/** called when a mw conversation and purple conversation come together,
    to inform the purple conversation of what features to offer the
    user */
static void convo_features(struct mwConversation *conv) {
  PurpleConversation *gconv;
  PurpleConnectionFlags feat;

  gconv = convo_get_gconv(conv);
  if(! gconv) return;

  feat = purple_conversation_get_features(gconv);

  if(mwConversation_isOpen(conv)) {
    if(mwConversation_supports(conv, mwImSend_HTML)) {
      feat |= PURPLE_CONNECTION_HTML;
    } else {
      feat &= ~PURPLE_CONNECTION_HTML;
    }

    if(mwConversation_supports(conv, mwImSend_MIME)) {
      feat &= ~PURPLE_CONNECTION_NO_IMAGES;
    } else {
      feat |= PURPLE_CONNECTION_NO_IMAGES;
    }

    DEBUG_INFO("conversation features set to 0x%04x\n", feat);
    purple_conversation_set_features(gconv, feat);

  } else {
    convo_nofeatures(conv);
  }
}


static void mw_conversation_opened(struct mwConversation *conv) {
  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleAccount *acct;

  struct convo_dat *cd;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;
  acct = purple_connection_get_account(gc);

  /* set up the queue */
  cd = mwConversation_getClientData(conv);
  if(cd) {
    convo_queue_send(conv);

    if(! convo_get_gconv(conv)) {
      mwConversation_free(conv);
      return;
    }

  } else {
    convo_data_new(conv);
  }

  { /* record the client key for the buddy */
    PurpleBuddy *buddy;
    struct mwLoginInfo *info;
    info = mwConversation_getTargetInfo(conv);

    buddy = purple_find_buddy(acct, info->user_id);
    if(buddy) {
      purple_blist_node_set_int((PurpleBlistNode *) buddy,
			      BUDDY_KEY_CLIENT, info->type);
    }
  }

  convo_features(conv);
}


static void mw_conversation_closed(struct mwConversation *conv,
				   guint32 reason) {

  struct convo_data *cd;

  g_return_if_fail(conv != NULL);

  /* if there's an error code and a non-typing message in the queue,
     print an error message to the conversation */
  cd = mwConversation_getClientData(conv);
  if(reason && cd && cd->queue) {
    GList *l;
    for(l = cd->queue; l; l = l->next) {
      struct convo_msg *m = l->data;
      if(m->type != mwImSend_TYPING) {
	convo_error(conv, reason);
	break;
      }
    }
  }

#if 0
  /* don't do this, to prevent the occasional weird sending of
     formatted messages as plaintext when the other end closes the
     conversation after we've begun composing the message */
  convo_nofeatures(conv);
#endif

  mwConversation_removeClientData(conv);
}


static void im_recv_text(struct mwConversation *conv,
			 struct mwPurplePluginData *pd,
			 const char *msg) {

  struct mwIdBlock *idb;
  char *txt, *esc;
  const char *t;

  idb = mwConversation_getTarget(conv);

  txt = purple_utf8_try_convert(msg);
  t = txt? txt: msg;

  esc = g_markup_escape_text(t, -1);
  serv_got_im(pd->gc, idb->user, esc, 0, time(NULL));
  g_free(esc);

  g_free(txt);
}


static void im_recv_typing(struct mwConversation *conv,
			   struct mwPurplePluginData *pd,
			   gboolean typing) {

  struct mwIdBlock *idb;
  idb = mwConversation_getTarget(conv);

  serv_got_typing(pd->gc, idb->user, 0,
		  typing? PURPLE_TYPING: PURPLE_NOT_TYPING);
}


static void im_recv_html(struct mwConversation *conv,
			 struct mwPurplePluginData *pd,
			 const char *msg) {
  struct mwIdBlock *idb;
  char *t1, *t2;
  const char *t;

  idb = mwConversation_getTarget(conv);

  /* ensure we're receiving UTF8 */
  t1 = purple_utf8_try_convert(msg);
  t = t1? t1: msg;

  /* convert entities to UTF8 so they'll log correctly */
  t2 = purple_utf8_ncr_decode(t);
  t = t2? t2: t;

  serv_got_im(pd->gc, idb->user, t, 0, time(NULL));

  g_free(t1);
  g_free(t2);
}


static void im_recv_subj(struct mwConversation *conv,
			 struct mwPurplePluginData *pd,
			 const char *subj) {

  /** @todo somehow indicate receipt of a conversation subject. It
      would also be nice if we added a /topic command for the
      protocol */
  ;
}


/** generate "cid:908@20582notesbuddy" from "<908@20582notesbuddy>" */
static char *make_cid(const char *cid) {
  gsize n;
  char *c, *d;

  g_return_val_if_fail(cid != NULL, NULL);

  n = strlen(cid);
  g_return_val_if_fail(n > 2, NULL);

  c = g_strndup(cid+1, n-2);
  d = g_strdup_printf("cid:%s", c);

  g_free(c);
  return d;
}


static void im_recv_mime(struct mwConversation *conv,
			 struct mwPurplePluginData *pd,
			 const char *data) {

  GHashTable *img_by_cid;
  GList *images;

  GString *str;

  PurpleMimeDocument *doc;
  GList *parts;

  img_by_cid = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  images = NULL;

  /* don't want the contained string to ever be NULL */
  str = g_string_new("");

  doc = purple_mime_document_parse(data);

  /* handle all the MIME parts */
  parts = purple_mime_document_get_parts(doc);
  for(; parts; parts = parts->next) {
    PurpleMimePart *part = parts->data;
    const char *type;

    type = purple_mime_part_get_field(part, "content-type");
    DEBUG_INFO("MIME part Content-Type: %s\n", NSTR(type));

    if(! type) {
      ; /* feh */

    } else if(purple_str_has_prefix(type, "image")) {
      /* put images into the image store */

      guchar *d_dat;
      gsize d_len;
      char *cid;
      int img;

      /* obtain and unencode the data */
      purple_mime_part_get_data_decoded(part, &d_dat, &d_len);

      /* look up the content id */
      cid = (char *) purple_mime_part_get_field(part, "Content-ID");
      cid = make_cid(cid);

      /* add image to the purple image store */
      img = purple_imgstore_add_with_id(d_dat, d_len, cid);

      /* map the cid to the image store identifier */
      g_hash_table_insert(img_by_cid, cid, GINT_TO_POINTER(img));

      /* recall the image for dereferencing later */
      images = g_list_append(images, GINT_TO_POINTER(img));

    } else if(purple_str_has_prefix(type, "text")) {

      /* concatenate all the text parts together */
      guchar *data;
      gsize len;

      purple_mime_part_get_data_decoded(part, &data, &len);
      g_string_append(str, (const char *)data);
      g_free(data);
    }
  }

  purple_mime_document_free(doc);

  /* @todo should put this in its own function */
  { /* replace each IMG tag's SRC attribute with an ID attribute. This
       actually modifies the contents of str */
    GData *attribs;
    char *start, *end;
    char *tmp = str->str;

    while(*tmp && purple_markup_find_tag("img", tmp, (const char **) &start,
				       (const char **) &end, &attribs)) {

      char *alt, *align, *border, *src;
      int img = 0;

      alt = g_datalist_get_data(&attribs, "alt");
      align = g_datalist_get_data(&attribs, "align");
      border = g_datalist_get_data(&attribs, "border");
      src = g_datalist_get_data(&attribs, "src");

      if(src)
	img = GPOINTER_TO_INT(g_hash_table_lookup(img_by_cid, src));

      if(img) {
	GString *atstr;
	gsize len = (end - start);
	gsize mov;

	atstr = g_string_new("");
	if(alt) g_string_append_printf(atstr, " alt=\"%s\"", alt);
	if(align) g_string_append_printf(atstr, " align=\"%s\"", align);
	if(border) g_string_append_printf(atstr, " border=\"%s\"", border);

	mov = g_snprintf(start, len, "<img%s id=\"%i\"", atstr->str, img);
	while(mov < len) start[mov++] = ' ';

	g_string_free(atstr, TRUE);
      }

      g_datalist_clear(&attribs);
      tmp = end + 1;
    }
  }

  im_recv_html(conv, pd, str->str);

  g_string_free(str, TRUE);

  /* clean up the cid table */
  g_hash_table_destroy(img_by_cid);

  /* dereference all the imgages */
  while(images) {
    purple_imgstore_unref_by_id(GPOINTER_TO_INT(images->data));
    images = g_list_delete_link(images, images);
  }
}


static void mw_conversation_recv(struct mwConversation *conv,
				 enum mwImSendType type,
				 gconstpointer msg) {
  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);

  switch(type) {
  case mwImSend_PLAIN:
    im_recv_text(conv, pd, msg);
    break;

  case mwImSend_TYPING:
    im_recv_typing(conv, pd, !! msg);
    break;

  case mwImSend_HTML:
    im_recv_html(conv, pd, msg);
    break;

  case mwImSend_SUBJECT:
    im_recv_subj(conv, pd, msg);
    break;

  case mwImSend_MIME:
    im_recv_mime(conv, pd, msg);
    break;

  default:
    DEBUG_INFO("conversation received strange type, 0x%04x\n", type);
    ; /* erm... */
  }
}


static void mw_place_invite(struct mwConversation *conv,
			    const char *message,
			    const char *title, const char *name) {
  struct mwServiceIm *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;

  struct mwIdBlock *idb;
  GHashTable *ht;

  srvc = mwConversation_getService(conv);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);

  idb = mwConversation_getTarget(conv);

  ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
  g_hash_table_insert(ht, CHAT_KEY_CREATOR, g_strdup(idb->user));
  g_hash_table_insert(ht, CHAT_KEY_NAME, g_strdup(name));
  g_hash_table_insert(ht, CHAT_KEY_TOPIC, g_strdup(title));
  g_hash_table_insert(ht, CHAT_KEY_INVITE, g_strdup(message));
  g_hash_table_insert(ht, CHAT_KEY_IS_PLACE, g_strdup("")); /* ugh */

  if(! title) title = "(no title)";
  if(! message) message = "(no message)";
  serv_got_chat_invite(pd->gc, title, idb->user, message, ht);

  mwConversation_close(conv, ERR_SUCCESS);
  mwConversation_free(conv);
}


static void mw_im_clear(struct mwServiceIm *srvc) {
  ;
}


static struct mwImHandler mw_im_handler = {
  mw_conversation_opened,
  mw_conversation_closed,
  mw_conversation_recv,
  mw_place_invite,
  mw_im_clear,
};


static struct mwServiceIm *mw_srvc_im_new(struct mwSession *s) {
  struct mwServiceIm *srvc;
  srvc = mwServiceIm_new(s, &mw_im_handler);
  mwServiceIm_setClientType(srvc, mwImClient_NOTESBUDDY);
  return srvc;
}


/* The following helps us relate a mwPlace to a PurpleConvChat in the
   various forms by which either may be indicated. Uses some of
   the similar macros from the conference service above */

#define PLACE_TO_ID(place)   (GPOINTER_TO_INT(place))
#define ID_TO_PLACE(pd, id)  (place_find_by_id((pd), (id)))

#define CHAT_TO_PLACE(pd, chat)  (ID_TO_PLACE((pd), CHAT_TO_ID(chat)))
#define PLACE_TO_CHAT(place)     (ID_TO_CHAT(PLACE_TO_ID(place)))


static struct mwPlace *
place_find_by_id(struct mwPurplePluginData *pd, int id) {
  struct mwServicePlace *srvc = pd->srvc_place;
  struct mwPlace *place = NULL;
  GList *l;

  l = (GList *) mwServicePlace_getPlaces(srvc);
  for(; l; l = l->next) {
    struct mwPlace *p = l->data;
    PurpleConvChat *h = PURPLE_CONV_CHAT(mwPlace_getClientData(p));

    if(CHAT_TO_ID(h) == id) {
      place = p;
      break;
    }
  }

  return place;
}


static void mw_place_opened(struct mwPlace *place) {
  struct mwServicePlace *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConversation *gconf;

  GList *members, *l;

  const char *n = mwPlace_getName(place);
  const char *t = mwPlace_getTitle(place);

  srvc = mwPlace_getService(place);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  members = mwPlace_getMembers(place);

  DEBUG_INFO("place %s opened, %u initial members\n",
	     NSTR(n), g_list_length(members));

  if(! t) t = "(no title)";
  gconf = serv_got_joined_chat(gc, PLACE_TO_ID(place), t);

  mwPlace_setClientData(place, gconf, NULL);

  for(l = members; l; l = l->next) {
    struct mwIdBlock *idb = l->data;
    purple_conv_chat_add_user(PURPLE_CONV_CHAT(gconf), idb->user,
			    NULL, PURPLE_CBFLAGS_NONE, FALSE);
  }
  g_list_free(members);
}


static void mw_place_closed(struct mwPlace *place, guint32 code) {
  struct mwServicePlace *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;

  const char *n = mwPlace_getName(place);
  char *msg = mwError(code);

  DEBUG_INFO("place %s closed, 0x%08x\n", NSTR(n), code);

  srvc = mwPlace_getService(place);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  serv_got_chat_left(gc, PLACE_TO_ID(place));

  purple_notify_error(gc, _("Place Closed"), NULL, msg);
  g_free(msg);
}


static void mw_place_peerJoined(struct mwPlace *place,
				const struct mwIdBlock *peer) {
  struct mwServicePlace *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConversation *gconf;

  const char *n = mwPlace_getName(place);

  DEBUG_INFO("%s joined place %s\n", NSTR(peer->user), NSTR(n));

  srvc = mwPlace_getService(place);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  gconf = mwPlace_getClientData(place);
  g_return_if_fail(gconf != NULL);

  purple_conv_chat_add_user(PURPLE_CONV_CHAT(gconf), peer->user,
			  NULL, PURPLE_CBFLAGS_NONE, TRUE);
}


static void mw_place_peerParted(struct mwPlace *place,
				const struct mwIdBlock *peer) {
  struct mwServicePlace *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  PurpleConversation *gconf;

  const char *n = mwPlace_getName(place);

  DEBUG_INFO("%s left place %s\n", NSTR(peer->user), NSTR(n));

  srvc = mwPlace_getService(place);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  gconf = mwPlace_getClientData(place);
  g_return_if_fail(gconf != NULL);

  purple_conv_chat_remove_user(PURPLE_CONV_CHAT(gconf), peer->user, NULL);
}


static void mw_place_peerSetAttribute(struct mwPlace *place,
				      const struct mwIdBlock *peer,
				      guint32 attr, struct mwOpaque *o) {
  ;
}


static void mw_place_peerUnsetAttribute(struct mwPlace *place,
					const struct mwIdBlock *peer,
					guint32 attr) {
  ;
}


static void mw_place_message(struct mwPlace *place,
			     const struct mwIdBlock *who,
			     const char *msg) {
  struct mwServicePlace *srvc;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;
  char *esc;

  if(! msg) return;

  srvc = mwPlace_getService(place);
  session = mwService_getSession(MW_SERVICE(srvc));
  pd = mwSession_getClientData(session);
  gc = pd->gc;

  esc = g_markup_escape_text(msg, -1);
  serv_got_chat_in(gc, PLACE_TO_ID(place), who->user, 0, esc, time(NULL));
  g_free(esc);
}


static void mw_place_clear(struct mwServicePlace *srvc) {
  ;
}


static struct mwPlaceHandler mw_place_handler = {
  mw_place_opened,
  mw_place_closed,
  mw_place_peerJoined,
  mw_place_peerParted,
  mw_place_peerSetAttribute,
  mw_place_peerUnsetAttribute,
  mw_place_message,
  mw_place_clear,
};


static struct mwServicePlace *mw_srvc_place_new(struct mwSession *s) {
  struct mwServicePlace *srvc;
  srvc = mwServicePlace_new(s, &mw_place_handler);
  return srvc;
}


static struct mwServiceResolve *mw_srvc_resolve_new(struct mwSession *s) {
  struct mwServiceResolve *srvc;
  srvc = mwServiceResolve_new(s);
  return srvc;
}


static struct mwServiceStorage *mw_srvc_store_new(struct mwSession *s) {
  struct mwServiceStorage *srvc;
  srvc = mwServiceStorage_new(s);
  return srvc;
}


/** allocate and associate a mwPurplePluginData with a PurpleConnection */
static struct mwPurplePluginData *mwPurplePluginData_new(PurpleConnection *gc) {
  struct mwPurplePluginData *pd;

  g_return_val_if_fail(gc != NULL, NULL);

  pd = g_new0(struct mwPurplePluginData, 1);
  pd->gc = gc;
  pd->session = mwSession_new(&mw_session_handler);
  pd->srvc_aware = mw_srvc_aware_new(pd->session);
  pd->srvc_conf = mw_srvc_conf_new(pd->session);
  pd->srvc_ft = mw_srvc_ft_new(pd->session);
  pd->srvc_im = mw_srvc_im_new(pd->session);
  pd->srvc_place = mw_srvc_place_new(pd->session);
  pd->srvc_resolve = mw_srvc_resolve_new(pd->session);
  pd->srvc_store = mw_srvc_store_new(pd->session);
  pd->group_list_map = g_hash_table_new(g_direct_hash, g_direct_equal);
  pd->sock_buf = purple_circ_buffer_new(0);

  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_aware));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_conf));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_ft));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_im));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_place));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_resolve));
  mwSession_addService(pd->session, MW_SERVICE(pd->srvc_store));

  mwSession_addCipher(pd->session, mwCipher_new_RC2_40(pd->session));
  mwSession_addCipher(pd->session, mwCipher_new_RC2_128(pd->session));

  mwSession_setClientData(pd->session, pd, NULL);
  gc->proto_data = pd;

  return pd;
}


static void mwPurplePluginData_free(struct mwPurplePluginData *pd) {
  g_return_if_fail(pd != NULL);

  pd->gc->proto_data = NULL;

  mwSession_removeService(pd->session, mwService_AWARE);
  mwSession_removeService(pd->session, mwService_CONFERENCE);
  mwSession_removeService(pd->session, mwService_FILE_TRANSFER);
  mwSession_removeService(pd->session, mwService_IM);
  mwSession_removeService(pd->session, mwService_PLACE);
  mwSession_removeService(pd->session, mwService_RESOLVE);
  mwSession_removeService(pd->session, mwService_STORAGE);

  mwService_free(MW_SERVICE(pd->srvc_aware));
  mwService_free(MW_SERVICE(pd->srvc_conf));
  mwService_free(MW_SERVICE(pd->srvc_ft));
  mwService_free(MW_SERVICE(pd->srvc_im));
  mwService_free(MW_SERVICE(pd->srvc_place));
  mwService_free(MW_SERVICE(pd->srvc_resolve));
  mwService_free(MW_SERVICE(pd->srvc_store));

  mwCipher_free(mwSession_getCipher(pd->session, mwCipher_RC2_40));
  mwCipher_free(mwSession_getCipher(pd->session, mwCipher_RC2_128));

  mwSession_free(pd->session);

  g_hash_table_destroy(pd->group_list_map);
  purple_circ_buffer_destroy(pd->sock_buf);

  g_free(pd);
}


static const char *mw_prpl_list_icon(PurpleAccount *a, PurpleBuddy *b) {
  /* my little green dude is a chopped up version of the aim running
     guy.  First, cut off the head and store someplace safe. Then,
     take the left-half side of the body and throw it away. Make a
     copy of the remaining body, and flip it horizontally. Now attach
     the two pieces into an X shape, and drop the head back on the
     top, being careful to center it. Then, just change the color
     saturation to bring the red down a bit, and voila! */

  /* then, throw all of that away and use sodipodi to make a new
     icon. You know, LIKE A REAL MAN. */

  return "meanwhile";
}


static const char* mw_prpl_list_emblem(PurpleBuddy *b)
{
  if(buddy_is_external(b))
    return "external";

  return NULL;
}


static char *mw_prpl_status_text(PurpleBuddy *b) {
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;
  struct mwAwareIdBlock t = { mwAware_USER, (char *)purple_buddy_get_name(b), NULL };
  const char *ret = NULL;

  if ((gc = purple_account_get_connection(purple_buddy_get_account(b)))
      && (pd = gc->proto_data))
    ret = mwServiceAware_getText(pd->srvc_aware, &t);

  return (ret && g_utf8_validate(ret, -1, NULL)) ? g_markup_escape_text(ret, -1): NULL;
}


static const char *status_text(PurpleBuddy *b) {
  PurplePresence *presence;
  PurpleStatus *status;

  presence = purple_buddy_get_presence(b);
  status = purple_presence_get_active_status(presence);

  return purple_status_get_name(status);
}


static gboolean user_supports(struct mwServiceAware *srvc,
			      const char *who, guint32 feature) {

  const struct mwAwareAttribute *attr;
  struct mwAwareIdBlock idb = { mwAware_USER, (char *) who, NULL };

  attr = mwServiceAware_getAttribute(srvc, &idb, feature);
  return (attr != NULL) && mwAwareAttribute_asBoolean(attr);
}


static char *user_supports_text(struct mwServiceAware *srvc, const char *who) {
  const char *feat[] = {NULL, NULL, NULL, NULL, NULL};
  const char **f = feat;

  if(user_supports(srvc, who, mwAttribute_AV_PREFS_SET)) {
    gboolean mic, speak, video;

    mic = user_supports(srvc, who, mwAttribute_MICROPHONE);
    speak = user_supports(srvc, who, mwAttribute_SPEAKERS);
    video = user_supports(srvc, who, mwAttribute_VIDEO_CAMERA);

    if(mic) *f++ = _("Microphone");
    if(speak) *f++ = _("Speakers");
    if(video) *f++ = _("Video Camera");
  }

  if(user_supports(srvc, who, mwAttribute_FILE_TRANSFER))
    *f++ = _("File Transfer");

  return (*feat)? g_strjoinv(", ", (char **)feat): NULL;
  /* jenni loves siege */
}


static void mw_prpl_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full) {
  PurpleConnection *gc;
  struct mwPurplePluginData *pd = NULL;
  struct mwAwareIdBlock idb = { mwAware_USER, (char *)purple_buddy_get_name(b), NULL };

  const char *message = NULL;
  const char *status;
  char *tmp;

  if ((gc = purple_account_get_connection(purple_buddy_get_account(b)))
      && (pd = gc->proto_data))
     message = mwServiceAware_getText(pd->srvc_aware, &idb);

  status = status_text(b);

  if(message != NULL && g_utf8_validate(message, -1, NULL) && purple_utf8_strcasecmp(status, message)) {
    tmp = g_markup_escape_text(message, -1);
	purple_notify_user_info_add_pair(user_info, status, tmp);
    g_free(tmp);

  } else {
	purple_notify_user_info_add_pair(user_info, _("Status"), status);
  }

  if(full && pd != NULL) {
    tmp = user_supports_text(pd->srvc_aware, purple_buddy_get_name(b));
    if(tmp) {
	  purple_notify_user_info_add_pair(user_info, _("Supports"), tmp);
      g_free(tmp);
    }

    if(buddy_is_external(b)) {
	  purple_notify_user_info_add_pair(user_info, NULL, _("External User"));
    }
  }
}

static GList *mw_prpl_status_types(PurpleAccount *acct)
{
	GList *types = NULL;
	PurpleStatusType *type;

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
			MW_STATE_ACTIVE, NULL, TRUE, TRUE, FALSE,
			MW_STATE_MESSAGE, _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY,
			MW_STATE_AWAY, NULL, TRUE, TRUE, FALSE,
			MW_STATE_MESSAGE, _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE,
			MW_STATE_BUSY, _("Do Not Disturb"), TRUE, TRUE, FALSE,
			MW_STATE_MESSAGE, _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_append(types, type);

	type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE,
			MW_STATE_OFFLINE, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	return types;
}


static void conf_create_prompt_cancel(PurpleBuddy *buddy,
				      PurpleRequestFields *fields) {
  ; /* nothing to do */
}


static void conf_create_prompt_join(PurpleBuddy *buddy,
				    PurpleRequestFields *fields) {
  PurpleAccount *acct;
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;
  struct mwServiceConference *srvc;

  PurpleRequestField *f;

  const char *topic, *invite;
  struct mwConference *conf;
  struct mwIdBlock idb = { NULL, NULL };

  acct = purple_buddy_get_account(buddy);
  gc = purple_account_get_connection(acct);
  pd = gc->proto_data;
  srvc = pd->srvc_conf;

  f = purple_request_fields_get_field(fields, CHAT_KEY_TOPIC);
  topic = purple_request_field_string_get_value(f);

  f = purple_request_fields_get_field(fields, CHAT_KEY_INVITE);
  invite = purple_request_field_string_get_value(f);

  conf = mwConference_new(srvc, topic);
  mwConference_open(conf);

  idb.user = (char *)purple_buddy_get_name(buddy);
  mwConference_invite(conf, &idb, invite);
}


static void blist_menu_conf_create(PurpleBuddy *buddy, const char *msg) {

  PurpleRequestFields *fields;
  PurpleRequestFieldGroup *g;
  PurpleRequestField *f;

  PurpleAccount *acct;
  PurpleConnection *gc;

  const char *msgA;
  const char *msgB;
  char *msg1;

  g_return_if_fail(buddy != NULL);

  acct = purple_buddy_get_account(buddy);
  g_return_if_fail(acct != NULL);

  gc = purple_account_get_connection(acct);
  g_return_if_fail(gc != NULL);

  fields = purple_request_fields_new();

  g = purple_request_field_group_new(NULL);
  purple_request_fields_add_group(fields, g);

  f = purple_request_field_string_new(CHAT_KEY_TOPIC, _("Topic"), NULL, FALSE);
  purple_request_field_group_add_field(g, f);

  f = purple_request_field_string_new(CHAT_KEY_INVITE, _("Message"), msg, FALSE);
  purple_request_field_group_add_field(g, f);

  msgA = _("Create conference with user");
  msgB = _("Please enter a topic for the new conference, and an invitation"
	   " message to be sent to %s");
  msg1 = g_strdup_printf(msgB, purple_buddy_get_name(buddy));

  purple_request_fields(gc, _("New Conference"),
		      msgA, msg1, fields,
		      _("Create"), G_CALLBACK(conf_create_prompt_join),
		      _("Cancel"), G_CALLBACK(conf_create_prompt_cancel),
			  acct, purple_buddy_get_name(buddy), NULL,
		      buddy);
  g_free(msg1);
}


static void conf_select_prompt_cancel(PurpleBuddy *buddy,
				      PurpleRequestFields *fields) {
  ;
}


static void conf_select_prompt_invite(PurpleBuddy *buddy,
				      PurpleRequestFields *fields) {
  PurpleRequestField *f;
  GList *l;
  const char *msg;

  f = purple_request_fields_get_field(fields, CHAT_KEY_INVITE);
  msg = purple_request_field_string_get_value(f);

  f = purple_request_fields_get_field(fields, "conf");
  l = purple_request_field_list_get_selected(f);

  if(l) {
    gpointer d = purple_request_field_list_get_data(f, l->data);

    if(GPOINTER_TO_INT(d) == 0x01) {
      blist_menu_conf_create(buddy, msg);

    } else {
      struct mwIdBlock idb = { (char *)purple_buddy_get_name(buddy), NULL };
      mwConference_invite(d, &idb, msg);
    }
  }
}


static void blist_menu_conf_list(PurpleBuddy *buddy,
				 GList *confs) {

  PurpleRequestFields *fields;
  PurpleRequestFieldGroup *g;
  PurpleRequestField *f;

  PurpleAccount *acct;
  PurpleConnection *gc;

  const char *msgA;
  const char *msgB;
  char *msg;

  acct = purple_buddy_get_account(buddy);
  g_return_if_fail(acct != NULL);

  gc = purple_account_get_connection(acct);
  g_return_if_fail(gc != NULL);

  fields = purple_request_fields_new();

  g = purple_request_field_group_new(NULL);
  purple_request_fields_add_group(fields, g);

  f = purple_request_field_list_new("conf", _("Available Conferences"));
  purple_request_field_list_set_multi_select(f, FALSE);
  for(; confs; confs = confs->next) {
    struct mwConference *c = confs->data;
    purple_request_field_list_add_icon(f, mwConference_getTitle(c), NULL, c);
  }
  purple_request_field_list_add_icon(f, _("Create New Conference..."),
			      NULL, GINT_TO_POINTER(0x01));
  purple_request_field_group_add_field(g, f);

  f = purple_request_field_string_new(CHAT_KEY_INVITE, "Message", NULL, FALSE);
  purple_request_field_group_add_field(g, f);

  msgA = _("Invite user to a conference");
  msgB = _("Select a conference from the list below to send an invite to"
	   " user %s. Select \"Create New Conference\" if you'd like to"
	   " create a new conference to invite this user to.");
  msg = g_strdup_printf(msgB, purple_buddy_get_name(buddy));

  purple_request_fields(gc, _("Invite to Conference"),
		      msgA, msg, fields,
		      _("Invite"), G_CALLBACK(conf_select_prompt_invite),
		      _("Cancel"), G_CALLBACK(conf_select_prompt_cancel),
			  acct, purple_buddy_get_name(buddy), NULL,
		      buddy);
  g_free(msg);
}


static void blist_menu_conf(PurpleBlistNode *node, gpointer data) {
  PurpleBuddy *buddy = (PurpleBuddy *) node;
  PurpleAccount *acct;
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;
  GList *l;

  g_return_if_fail(node != NULL);
  g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

  acct = purple_buddy_get_account(buddy);
  g_return_if_fail(acct != NULL);

  gc = purple_account_get_connection(acct);
  g_return_if_fail(gc != NULL);

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  /*
    - get a list of all conferences on this session
    - if none, prompt to create one, and invite buddy to it
    - else, prompt to select a conference or create one
  */

  l = mwServiceConference_getConferences(pd->srvc_conf);
  if(l) {
    blist_menu_conf_list(buddy, l);
    g_list_free(l);

  } else {
    blist_menu_conf_create(buddy, NULL);
  }
}


#if 0
static void blist_menu_announce(PurpleBlistNode *node, gpointer data) {
  PurpleBuddy *buddy = (PurpleBuddy *) node;
  PurpleAccount *acct;
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;
  struct mwSession *session;
  char *rcpt_name;
  GList *rcpt;

  g_return_if_fail(node != NULL);
  g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

  acct = buddy->account;
  g_return_if_fail(acct != NULL);

  gc = purple_account_get_connection(acct);
  g_return_if_fail(gc != NULL);

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  rcpt_name = g_strdup_printf("@U %s", buddy->name);
  rcpt = g_list_prepend(NULL, rcpt_name);

  session = pd->session;
  mwSession_sendAnnounce(session, FALSE,
			 "This is a TEST announcement. Please ignore.",
			 rcpt);

  g_list_free(rcpt);
  g_free(rcpt_name);
}
#endif


static GList *mw_prpl_blist_node_menu(PurpleBlistNode *node) {
  GList *l = NULL;
  PurpleMenuAction *act;

  if(! PURPLE_BLIST_NODE_IS_BUDDY(node))
    return l;

  l = g_list_append(l, NULL);

  act = purple_menu_action_new(_("Invite to Conference..."),
                             PURPLE_CALLBACK(blist_menu_conf), NULL, NULL);
  l = g_list_append(l, act);

#if 0
  act = purple_menu_action_new(_("Send TEST Announcement"),
			     PURPLE_CALLBACK(blist_menu_announce), NULL, NULL);
  l = g_list_append(l, act);
#endif

  /** note: this never gets called for a PurpleGroup, have to use the
      blist-node-extended-menu signal for that. The function
      blist_node_menu_cb is assigned to this signal in the function
      services_starting */

  return l;
}


static GList *mw_prpl_chat_info(PurpleConnection *gc) {
  GList *l = NULL;
  struct proto_chat_entry *pce;

  pce = g_new0(struct proto_chat_entry, 1);
  pce->label = _("Topic:");
  pce->identifier = CHAT_KEY_TOPIC;
  l = g_list_append(l, pce);

  return l;
}


static GHashTable *mw_prpl_chat_info_defaults(PurpleConnection *gc,
					      const char *name) {
  GHashTable *table;

  g_return_val_if_fail(gc != NULL, NULL);

  table = g_hash_table_new_full(g_str_hash, g_str_equal,
				NULL, g_free);

  g_hash_table_insert(table, CHAT_KEY_NAME, g_strdup(name));
  g_hash_table_insert(table, CHAT_KEY_INVITE, NULL);

  return table;
}


static void mw_prpl_login(PurpleAccount *acct);


static void mw_prpl_login(PurpleAccount *account) {
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;

  char *user, *pass, *host;
  guint port;

  gc = purple_account_get_connection(account);
  pd = mwPurplePluginData_new(gc);

  /* while we do support images, the default is to not offer it */
  gc->flags |= PURPLE_CONNECTION_NO_IMAGES;

  user = g_strdup(purple_account_get_username(account));

  host = strrchr(user, ':');
  if(host) {
    /* annoying user split from 1.2.0, need to undo it */
    *host++ = '\0';
    purple_account_set_string(account, MW_KEY_HOST, host);
    purple_account_set_username(account, user);

  } else {
    host = (char *) purple_account_get_string(account, MW_KEY_HOST,
					    MW_PLUGIN_DEFAULT_HOST);
  }

  if(! host || ! *host) {
    /* somehow, we don't have a host to connect to. Well, we need one
       to actually continue, so let's ask the user directly. */
    g_free(user);
    purple_connection_error_reason(gc,
            PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
            _("A server is required to connect this account"));
    return;
  }

  pass = g_strdup(purple_account_get_password(account));
  port = purple_account_get_int(account, MW_KEY_PORT, MW_PLUGIN_DEFAULT_PORT);

  DEBUG_INFO("user: '%s'\n", user);
  DEBUG_INFO("host: '%s'\n", host);
  DEBUG_INFO("port: %u\n", port);

  mwSession_setProperty(pd->session, mwSession_NO_SECRET,
			(char *) no_secret, NULL);
  mwSession_setProperty(pd->session, mwSession_AUTH_USER_ID, user, g_free);
  mwSession_setProperty(pd->session, mwSession_AUTH_PASSWORD, pass, g_free);

  if(purple_account_get_bool(account, MW_KEY_FAKE_IT, FALSE)) {
    guint client, major, minor;

    /* if we're faking the login, let's also fake the version we're
       reporting. Let's also allow the actual values to be specified */

    client = purple_account_get_int(account, MW_KEY_CLIENT, mwLogin_BINARY);
    major = purple_account_get_int(account, MW_KEY_MAJOR, 0x001e);
    minor = purple_account_get_int(account, MW_KEY_MINOR, 0x196f);

    DEBUG_INFO("client id: 0x%04x\n", client);
    DEBUG_INFO("client major: 0x%04x\n", major);
    DEBUG_INFO("client minor: 0x%04x\n", minor);

    mwSession_setProperty(pd->session, mwSession_CLIENT_TYPE_ID,
			  GUINT_TO_POINTER(client), NULL);

    mwSession_setProperty(pd->session, mwSession_CLIENT_VER_MAJOR,
			  GUINT_TO_POINTER(major), NULL);

    mwSession_setProperty(pd->session, mwSession_CLIENT_VER_MINOR,
			  GUINT_TO_POINTER(minor), NULL);
  }

  purple_connection_update_progress(gc, _("Connecting"), 1, MW_CONNECT_STEPS);

  if (purple_proxy_connect(gc, account, host, port, connect_cb, pd) == NULL) {
    purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                                   _("Unable to connect"));
  }
}


static void mw_prpl_close(PurpleConnection *gc) {
  struct mwPurplePluginData *pd;

  g_return_if_fail(gc != NULL);

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  /* get rid of the blist save timeout */
  if(pd->save_event) {
    purple_timeout_remove(pd->save_event);
    pd->save_event = 0;
    blist_store(pd);
  }

  /* stop the session */
  mwSession_stop(pd->session, 0x00);

  /* no longer necessary */
  gc->proto_data = NULL;

  /* stop watching the socket */
  if(gc->inpa) {
    purple_input_remove(gc->inpa);
    gc->inpa = 0;
  }

  /* clean up the rest */
  mwPurplePluginData_free(pd);
}


static int mw_rand(void) {
  static int seed = 0;

  /* for diversity, not security. don't touch */
  srand(time(NULL) ^ seed);
  seed = rand();

  return seed;
}


/** generates a random-ish content id string */
static char *im_mime_content_id(void) {
  return g_strdup_printf("%03x@%05xmeanwhile",
			 mw_rand() & 0xfff, mw_rand() & 0xfffff);
}


/** generates a multipart/related content type with a random-ish
    boundary value */
static char *im_mime_content_type(void) {
  return g_strdup_printf("multipart/related; boundary=related_MW%03x_%04x",
                         mw_rand() & 0xfff, mw_rand() & 0xffff);
}


/** determine content type from extension. Not so happy about this,
    but I don't want to actually write image type detection */
static char *im_mime_img_content_type(PurpleStoredImage *img) {
  const char *fn = purple_imgstore_get_filename(img);
  const char *ct = NULL;

  ct = strrchr(fn, '.');
  if(! ct) {
    ct = "image";

  } else if(! strcmp(".png", ct)) {
    ct = "image/png";

  } else if(! strcmp(".jpg", ct)) {
    ct = "image/jpeg";

  } else if(! strcmp(".jpeg", ct)) {
    ct = "image/jpeg";

  } else if(! strcmp(".gif", ct)) {
    ct = "image/gif";

  } else {
    ct = "image";
  }

  return g_strdup_printf("%s; name=\"%s\"", ct, fn);
}


static char *im_mime_img_content_disp(PurpleStoredImage *img) {
  const char *fn = purple_imgstore_get_filename(img);
  return g_strdup_printf("attachment; filename=\"%s\"", fn);
}


/** turn an IM with embedded images into a multi-part mime document */
static char *im_mime_convert(PurpleConnection *gc,
			     struct mwConversation *conv,
			     const char *message) {
  GString *str;
  PurpleMimeDocument *doc;
  PurpleMimePart *part;

  GData *attr;
  char *tmp, *start, *end;

  str = g_string_new(NULL);

  doc = purple_mime_document_new();

  purple_mime_document_set_field(doc, "Mime-Version", "1.0");
  purple_mime_document_set_field(doc, "Content-Disposition", "inline");

  tmp = im_mime_content_type();
  purple_mime_document_set_field(doc, "Content-Type", tmp);
  g_free(tmp);

  tmp = (char *) message;
  while(*tmp && purple_markup_find_tag("img", tmp, (const char **) &start,
				     (const char **) &end, &attr)) {
    char *id;
    PurpleStoredImage *img = NULL;

    gsize len = (start - tmp);

    /* append the in-between-tags text */
    if(len) g_string_append_len(str, tmp, len);

    /* find the imgstore data by the id tag */
    id = g_datalist_get_data(&attr, "id");
    if(id && *id)
      img = purple_imgstore_find_by_id(atoi(id));

    if(img) {
      char *cid;
      gpointer data;
      size_t size;

      part = purple_mime_part_new(doc);

      data = im_mime_img_content_disp(img);
      purple_mime_part_set_field(part, "Content-Disposition", data);
      g_free(data);

      data = im_mime_img_content_type(img);
      purple_mime_part_set_field(part, "Content-Type", data);
      g_free(data);

      cid = im_mime_content_id();
      data = g_strdup_printf("<%s>", cid);
      purple_mime_part_set_field(part, "Content-ID", data);
      g_free(data);

      purple_mime_part_set_field(part, "Content-transfer-encoding", "base64");

      /* obtain and base64 encode the image data, and put it in the
	 mime part */
      size = purple_imgstore_get_size(img);
      data = purple_base64_encode(purple_imgstore_get_data(img), (gsize) size);
      purple_mime_part_set_data(part, data);
      g_free(data);

      /* append the modified tag */
      g_string_append_printf(str, "<img src=\"cid:%s\">", cid);
      g_free(cid);

    } else {
      /* append the literal image tag, since we couldn't find a
	 relative imgstore object */
      gsize len = (end - start) + 1;
      g_string_append_len(str, start, len);
    }

    g_datalist_clear(&attr);
    tmp = end + 1;
  }

  /* append left-overs */
  g_string_append(str, tmp);

  /* add the text/html part */
  part = purple_mime_part_new(doc);
  purple_mime_part_set_field(part, "Content-Disposition", "inline");

  tmp = purple_utf8_ncr_encode(str->str);
  purple_mime_part_set_field(part, "Content-Type", "text/html");
  purple_mime_part_set_field(part, "Content-Transfer-Encoding", "7bit");
  purple_mime_part_set_data(part, tmp);
  g_free(tmp);

  g_string_free(str, TRUE);

  str = g_string_new(NULL);
  purple_mime_document_write(doc, str);
  tmp = str->str;
  g_string_free(str, FALSE);

  return tmp;
}


static int mw_prpl_send_im(PurpleConnection *gc,
			   const char *name,
			   const char *message,
			   PurpleMessageFlags flags) {

  struct mwPurplePluginData *pd;
  struct mwIdBlock who = { (char *) name, NULL };
  struct mwConversation *conv;

  g_return_val_if_fail(gc != NULL, 0);
  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);

  conv = mwServiceIm_getConversation(pd->srvc_im, &who);

  /* this detection of features to determine how to send the message
     (plain, html, or mime) is flawed because the other end of the
     conversation could close their channel at any time, rendering any
     existing formatting in an outgoing message innapropriate. The end
     result is that it may be possible that the other side of the
     conversation will receive a plaintext message with html contents,
     which is bad. I'm not sure how to fix this correctly. */

  if(strstr(message, "<img ") || strstr(message, "<IMG "))
    flags |= PURPLE_MESSAGE_IMAGES;

  if(mwConversation_isOpen(conv)) {
    char *tmp;
    int ret;

    if((flags & PURPLE_MESSAGE_IMAGES) &&
       mwConversation_supports(conv, mwImSend_MIME)) {
      /* send a MIME message */

      tmp = im_mime_convert(gc, conv, message);
      ret = mwConversation_send(conv, mwImSend_MIME, tmp);
      g_free(tmp);

    } else if(mwConversation_supports(conv, mwImSend_HTML)) {
      /* send an HTML message */

      char *ncr;
      ncr = purple_utf8_ncr_encode(message);
      tmp = purple_strdup_withhtml(ncr);
      g_free(ncr);

      ret = mwConversation_send(conv, mwImSend_HTML, tmp);
      g_free(tmp);

    } else {
      /* default to text */
      tmp = purple_markup_strip_html(message);
      ret = mwConversation_send(conv, mwImSend_PLAIN, tmp);
      g_free(tmp);
    }

    return !ret;

  } else {

    /* queue up the message safely as plain text */
    char *tmp = purple_markup_strip_html(message);
    convo_queue(conv, mwImSend_PLAIN, tmp);
    g_free(tmp);

    if(! mwConversation_isPending(conv))
      mwConversation_open(conv);

    return 1;
  }
}


static unsigned int mw_prpl_send_typing(PurpleConnection *gc,
					const char *name,
					PurpleTypingState state) {

  struct mwPurplePluginData *pd;
  struct mwIdBlock who = { (char *) name, NULL };
  struct mwConversation *conv;

  gpointer t = GINT_TO_POINTER(!! state);

  g_return_val_if_fail(gc != NULL, 0);
  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);

  conv = mwServiceIm_getConversation(pd->srvc_im, &who);

  if(mwConversation_isOpen(conv)) {
    mwConversation_send(conv, mwImSend_TYPING, t);

  } else if((state == PURPLE_TYPING) || (state == PURPLE_TYPED)) {
    /* only open a channel for sending typing notification, not for
       when typing has stopped. There's no point in re-opening a
       channel just to tell someone that this side isn't typing. */

    convo_queue(conv, mwImSend_TYPING, t);

    if(! mwConversation_isPending(conv)) {
      mwConversation_open(conv);
    }
  }

  return 0;
}


static const char *mw_client_name(guint16 type) {
  switch(type) {
  case mwLogin_LIB:
    return "Lotus Binary Library";

  case mwLogin_JAVA_WEB:
    return "Lotus Java Client Applet";

  case mwLogin_BINARY:
    return "Lotus Sametime Connect";

  case mwLogin_JAVA_APP:
    return "Lotus Java Client Application";

  case mwLogin_LINKS:
    return "Lotus Sametime Links";

  case mwLogin_NOTES_6_5:
  case mwLogin_NOTES_6_5_3:
  case mwLogin_NOTES_7_0_beta:
  case mwLogin_NOTES_7_0:
    return "Lotus Notes Client";

  case mwLogin_ICT:
  case mwLogin_ICT_1_7_8_2:
  case mwLogin_ICT_SIP:
    return "IBM Community Tools";

  case mwLogin_NOTESBUDDY_4_14:
  case mwLogin_NOTESBUDDY_4_15:
  case mwLogin_NOTESBUDDY_4_16:
    return "Alphaworks NotesBuddy";

  case 0x1305:
  case 0x1306:
  case 0x1307:
    return "Lotus Sametime Connect 7.5";

  case mwLogin_SANITY:
    return "Sanity";

  case mwLogin_ST_PERL:
    return "ST-Send-Message";

  case mwLogin_TRILLIAN:
  case mwLogin_TRILLIAN_IBM:
    return "Trillian";

  case mwLogin_MEANWHILE:
    return "Meanwhile";

  default:
    return NULL;
  }
}


static void mw_prpl_get_info(PurpleConnection *gc, const char *who) {

  struct mwAwareIdBlock idb = { mwAware_USER, (char *) who, NULL };

  struct mwPurplePluginData *pd;
  PurpleAccount *acct;
  PurpleBuddy *b;
  PurpleNotifyUserInfo *user_info;
  char *tmp;
  const char *tmp2;

  g_return_if_fail(who != NULL);
  g_return_if_fail(*who != '\0');

  pd = gc->proto_data;

  acct = purple_connection_get_account(gc);
  b = purple_find_buddy(acct, who);
  user_info = purple_notify_user_info_new();

  if(purple_str_has_prefix(who, "@E ")) {
	purple_notify_user_info_add_pair(user_info, _("External User"), NULL);
  }

  purple_notify_user_info_add_pair(user_info, _("User ID"), who);

  if(b) {
    guint32 type;

    if(purple_buddy_get_server_alias(b)) {
		purple_notify_user_info_add_pair(user_info, _("Full Name"), purple_buddy_get_server_alias(b));
    }

    type = purple_blist_node_get_int((PurpleBlistNode *) b, BUDDY_KEY_CLIENT);
    if(type) {
	  tmp = g_strdup(mw_client_name(type));
	  if (!tmp)
		tmp = g_strdup_printf(_("Unknown (0x%04x)<br>"), type);

	  purple_notify_user_info_add_pair(user_info, _("Last Known Client"), tmp);

	  g_free(tmp);
    }
  }

  tmp = user_supports_text(pd->srvc_aware, who);
  if(tmp) {
	purple_notify_user_info_add_pair(user_info, _("Supports"), tmp);
	g_free(tmp);
  }

  if(b) {
	purple_notify_user_info_add_pair(user_info, _("Status"), status_text(b));

	/* XXX Is this adding a status message in its own section rather than with the "Status" label? */
    tmp2 = mwServiceAware_getText(pd->srvc_aware, &idb);
    if(tmp2 && g_utf8_validate(tmp2, -1, NULL)) {
      tmp = g_markup_escape_text(tmp2, -1);
	  purple_notify_user_info_add_section_break(user_info);
	  purple_notify_user_info_add_pair(user_info, NULL, tmp);
      g_free(tmp);
    }
  }

  /* @todo emit a signal to allow a plugin to override the display of
     this notification, so that it can create its own */

  purple_notify_userinfo(gc, who, user_info, NULL, NULL);
  purple_notify_user_info_destroy(user_info);
}


static void mw_prpl_set_status(PurpleAccount *acct, PurpleStatus *status) {
  PurpleConnection *gc;
  const char *state;
  char *message = NULL;
  struct mwSession *session;
  struct mwUserStatus stat;

  g_return_if_fail(acct != NULL);
  gc = purple_account_get_connection(acct);

  state = purple_status_get_id(status);

  DEBUG_INFO("Set status to %s\n", purple_status_get_name(status));

  g_return_if_fail(gc != NULL);

  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  /* get a working copy of the current status */
  mwUserStatus_clone(&stat, mwSession_getUserStatus(session));

  /* determine the state */
  if(! strcmp(state, MW_STATE_ACTIVE)) {
    stat.status = mwStatus_ACTIVE;

  } else if(! strcmp(state, MW_STATE_AWAY)) {
    stat.status = mwStatus_AWAY;

  } else if(! strcmp(state, MW_STATE_BUSY)) {
    stat.status = mwStatus_BUSY;
  }

  /* determine the message */
  message = (char *) purple_status_get_attr_string(status, MW_STATE_MESSAGE);

  if(message) {
    /* all the possible non-NULL values of message up to this point
       are const, so we don't need to free them */
    message = purple_markup_strip_html(message);
  }

  /* out with the old */
  g_free(stat.desc);

  /* in with the new */
  stat.desc = (char *) message;

  mwSession_setUserStatus(session, &stat);
  mwUserStatus_clear(&stat);
}


static void mw_prpl_set_idle(PurpleConnection *gc, int t) {
  struct mwSession *session;
  struct mwUserStatus stat;


  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  mwUserStatus_clone(&stat, mwSession_getUserStatus(session));

  if(t) {
    time_t now = time(NULL);
    stat.time = now - t;

  } else {
    stat.time = 0;
  }

  if(t > 0 && stat.status == mwStatus_ACTIVE) {
    /* we were active and went idle, so change the status to IDLE. */
    stat.status = mwStatus_IDLE;

  } else if(t == 0 && stat.status == mwStatus_IDLE) {
    /* we only become idle automatically, so change back to ACTIVE */
    stat.status = mwStatus_ACTIVE;
  }

  mwSession_setUserStatus(session, &stat);
  mwUserStatus_clear(&stat);
}


static void notify_im(PurpleConnection *gc, GList *row, void *user_data) {
  PurpleAccount *acct;
  PurpleConversation *conv;
  char *id;

  acct = purple_connection_get_account(gc);
  id = g_list_nth_data(row, 1);
  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, id, acct);
  if(! conv) conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
  purple_conversation_present(conv);
}


static void notify_add(PurpleConnection *gc, GList *row, void *user_data) {
  BuddyAddData *data = user_data;
  const char *group_name = NULL;

  if (data && data->group) {
    group_name = purple_group_get_name(data->group);
  }

  purple_blist_request_add_buddy(purple_connection_get_account(gc),
			       g_list_nth_data(row, 1), group_name,
			       g_list_nth_data(row, 0));
}


static void notify_close(gpointer data) {
  if (data) {
    g_free(data);
  }
}


static void multi_resolved_query(struct mwResolveResult *result,
				 PurpleConnection *gc, gpointer data) {
  GList *l;
  const char *msgA;
  const char *msgB;
  char *msg;

  PurpleNotifySearchResults *sres;
  PurpleNotifySearchColumn *scol;

  sres = purple_notify_searchresults_new();

  scol = purple_notify_searchresults_column_new(_("User Name"));
  purple_notify_searchresults_column_add(sres, scol);

  scol = purple_notify_searchresults_column_new(_("Sametime ID"));
  purple_notify_searchresults_column_add(sres, scol);

  purple_notify_searchresults_button_add(sres, PURPLE_NOTIFY_BUTTON_IM,
				       notify_im);

  purple_notify_searchresults_button_add(sres, PURPLE_NOTIFY_BUTTON_ADD,
				       notify_add);

  for(l = result->matches; l; l = l->next) {
    struct mwResolveMatch *match = l->data;
    GList *row = NULL;

    DEBUG_INFO("multi resolve: %s, %s\n",
	       NSTR(match->id), NSTR(match->name));

    if(!match->id || !match->name)
      continue;

    row = g_list_append(row, g_strdup(match->name));
    row = g_list_append(row, g_strdup(match->id));
    purple_notify_searchresults_row_add(sres, row);
  }

  msgA = _("An ambiguous user ID was entered");
  msgB = _("The identifier '%s' may possibly refer to any of the following"
	   " users. Please select the correct user from the list below to"
	   " add them to your buddy list.");
  msg = g_strdup_printf(msgB, result->name);

  purple_notify_searchresults(gc, _("Select User"),
			    msgA, msg, sres, notify_close, data);

  g_free(msg);
}


static void add_buddy_resolved(struct mwServiceResolve *srvc,
			       guint32 id, guint32 code, GList *results,
			       gpointer b) {

  struct mwResolveResult *res = NULL;
  BuddyAddData *data = b;
  PurpleBuddy *buddy = NULL;
  PurpleConnection *gc;
  struct mwPurplePluginData *pd;

  g_return_if_fail(data != NULL);

  buddy = data->buddy;

  gc = purple_account_get_connection(purple_buddy_get_account(buddy));
  pd = gc->proto_data;

  if(results)
    res = results->data;

  if(!code && res && res->matches) {
    if(!res->matches->next) {
      struct mwResolveMatch *match = res->matches->data;

      /* only one? that might be the right one! */
      if(strcmp(res->name, match->id)) {
	/* uh oh, the single result isn't identical to the search
	   term, better safe then sorry, so let's make sure it's who
	   the user meant to add */
	purple_blist_remove_buddy(buddy);
	multi_resolved_query(res, gc, data);

      } else {

	/* same person, set the server alias */
	purple_blist_server_alias_buddy(buddy, match->name);
	purple_blist_node_set_string((PurpleBlistNode *) buddy,
				   BUDDY_KEY_NAME, match->name);

	/* subscribe to awareness */
	buddy_add(pd, buddy);

	blist_schedule(pd);

        g_free(data);
      }

    } else {
      /* prompt user if more than one match was returned */
      purple_blist_remove_buddy(buddy);
      multi_resolved_query(res, gc, data);
    }

    return;
  }

#if 0
  /* fall-through indicates that we couldn't find a matching user in
     the resolve service (ether error or zero results), so we remove
     this buddy */

  /* note: I can't really think of a good reason to alter the buddy
     list in any way. There has been at least one report where the
     resolve service isn't returning correct results anyway, so let's
     just leave them in the list. I'm just going to if0 this section
     out unless I can think of a very good reason to do this. -siege */

  DEBUG_INFO("no such buddy in community\n");
  purple_blist_remove_buddy(buddy);
  blist_schedule(pd);

  if(res && res->name) {
    /* compose and display an error message */
    const char *msgA;
    const char *msgB;
    char *msg;

    msgA = _("Unable to add user: user not found");

    msgB = _("The identifier '%s' did not match any users in your"
	     " Sametime community. This entry has been removed from"
	     " your buddy list.");
    msg = g_strdup_printf(msgB, NSTR(res->name));

    purple_notify_error(gc, _("Unable to add user"), msgA, msg);

    g_free(msg);
  }
#endif
}


static void mw_prpl_add_buddy(PurpleConnection *gc,
			      PurpleBuddy *buddy,
			      PurpleGroup *group) {

  struct mwPurplePluginData *pd = gc->proto_data;
  struct mwServiceResolve *srvc;
  GList *query;
  enum mwResolveFlag flags;
  guint32 req;
  BuddyAddData *data;

  /* catch external buddies. They won't be in the resolve service */
  if(buddy_is_external(buddy)) {
    buddy_add(pd, buddy);
    return;
  }

  data = g_new0(BuddyAddData, 1);
  data->buddy = buddy;
  data->group = group;

  srvc = pd->srvc_resolve;

  query = g_list_prepend(NULL, (char *)purple_buddy_get_name(buddy));
  flags = mwResolveFlag_FIRST | mwResolveFlag_USERS;

  req = mwServiceResolve_resolve(srvc, query, flags, add_buddy_resolved,
				 data, NULL);
  g_list_free(query);

  if(req == SEARCH_ERROR) {
    purple_blist_remove_buddy(buddy);
    blist_schedule(pd);
  }
}


static void foreach_add_buddies(PurpleGroup *group, GList *buddies,
				struct mwPurplePluginData *pd) {
  struct mwAwareList *list;

  list = list_ensure(pd, group);
  mwAwareList_addAware(list, buddies);
  g_list_free(buddies);
}


static void mw_prpl_add_buddies(PurpleConnection *gc,
				GList *buddies,
				GList *groups) {

  struct mwPurplePluginData *pd;
  GHashTable *group_sets;
  struct mwAwareIdBlock *idbs, *idb;

  pd = gc->proto_data;

  /* map PurpleGroup:GList of mwAwareIdBlock */
  group_sets = g_hash_table_new(g_direct_hash, g_direct_equal);

  /* bunch of mwAwareIdBlock allocated at once, free'd at once */
  idb = idbs = g_new(struct mwAwareIdBlock, g_list_length(buddies));

  /* first pass collects mwAwareIdBlock lists for each group */
  for(; buddies; buddies = buddies->next) {
    PurpleBuddy *b = buddies->data;
    PurpleGroup *g;
    const char *fn;
    GList *l;

    /* nab the saved server alias and stick it on the buddy */
    fn = purple_blist_node_get_string((PurpleBlistNode *) b, BUDDY_KEY_NAME);
    purple_blist_server_alias_buddy(b, fn);

    /* convert PurpleBuddy into a mwAwareIdBlock */
    idb->type = mwAware_USER;
    idb->user = (char *) purple_buddy_get_name(b);
    idb->community = NULL;

    /* put idb into the list associated with the buddy's group */
    g = purple_buddy_get_group(b);
    l = g_hash_table_lookup(group_sets, g);
    l = g_list_prepend(l, idb++);
    g_hash_table_insert(group_sets, g, l);
  }

  /* each group's buddies get added in one shot, and schedule the blist
     for saving */
  g_hash_table_foreach(group_sets, (GHFunc) foreach_add_buddies, pd);
  blist_schedule(pd);

  /* cleanup */
  g_hash_table_destroy(group_sets);
  g_free(idbs);
}


static void mw_prpl_remove_buddy(PurpleConnection *gc,
				 PurpleBuddy *buddy, PurpleGroup *group) {

  struct mwPurplePluginData *pd;
  struct mwAwareIdBlock idb = { mwAware_USER, (char *)purple_buddy_get_name(buddy), NULL };
  struct mwAwareList *list;

  GList *rem = g_list_prepend(NULL, &idb);

  pd = gc->proto_data;
  group = purple_buddy_get_group(buddy);
  list = list_ensure(pd, group);

  mwAwareList_removeAware(list, rem);
  blist_schedule(pd);

  g_list_free(rem);
}


static void privacy_fill(struct mwPrivacyInfo *priv,
			 GSList *members) {

  struct mwUserItem *u;
  guint count;

  count = g_slist_length(members);
  DEBUG_INFO("privacy_fill: %u members\n", count);

  priv->count = count;
  priv->users = g_new0(struct mwUserItem, count);

  while(count--) {
    u = priv->users + count;
    u->id = members->data;
    members = members->next;
  }
}


static void mw_prpl_set_permit_deny(PurpleConnection *gc) {
  PurpleAccount *acct;
  struct mwPurplePluginData *pd;
  struct mwSession *session;

  struct mwPrivacyInfo privacy = {
    FALSE, /* deny  */
    0,     /* count */
    NULL,  /* users */
  };

  g_return_if_fail(gc != NULL);

  acct = purple_connection_get_account(gc);
  g_return_if_fail(acct != NULL);

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  session = pd->session;
  g_return_if_fail(session != NULL);

  switch(acct->perm_deny) {
  case PURPLE_PRIVACY_DENY_USERS:
    DEBUG_INFO("PURPLE_PRIVACY_DENY_USERS\n");
    privacy_fill(&privacy, acct->deny);
    privacy.deny = TRUE;
    break;

  case PURPLE_PRIVACY_ALLOW_ALL:
    DEBUG_INFO("PURPLE_PRIVACY_ALLOW_ALL\n");
    privacy.deny = TRUE;
    break;

  case PURPLE_PRIVACY_ALLOW_USERS:
    DEBUG_INFO("PURPLE_PRIVACY_ALLOW_USERS\n");
    privacy_fill(&privacy, acct->permit);
    privacy.deny = FALSE;
    break;

  case PURPLE_PRIVACY_DENY_ALL:
    DEBUG_INFO("PURPLE_PRIVACY_DENY_ALL\n");
    privacy.deny = FALSE;
    break;

  default:
    DEBUG_INFO("acct->perm_deny is 0x%x\n", acct->perm_deny);
    return;
  }

  mwSession_setPrivacyInfo(session, &privacy);
  g_free(privacy.users);
}


static void mw_prpl_add_permit(PurpleConnection *gc, const char *name) {
  mw_prpl_set_permit_deny(gc);
}


static void mw_prpl_add_deny(PurpleConnection *gc, const char *name) {
  mw_prpl_set_permit_deny(gc);
}


static void mw_prpl_rem_permit(PurpleConnection *gc, const char *name) {
  mw_prpl_set_permit_deny(gc);
}


static void mw_prpl_rem_deny(PurpleConnection *gc, const char *name) {
  mw_prpl_set_permit_deny(gc);
}


static struct mwConference *conf_find(struct mwServiceConference *srvc,
				      const char *name) {
  GList *l, *ll;
  struct mwConference *conf = NULL;

  ll = mwServiceConference_getConferences(srvc);
  for(l = ll; l; l = l->next) {
    struct mwConference *c = l->data;
    if(! strcmp(name, mwConference_getName(c))) {
      conf = c;
      break;
    }
  }
  g_list_free(ll);

  return conf;
}


static void mw_prpl_join_chat(PurpleConnection *gc,
			      GHashTable *components) {

  struct mwPurplePluginData *pd;
  char *c, *t;

  pd = gc->proto_data;

  c = g_hash_table_lookup(components, CHAT_KEY_NAME);
  t = g_hash_table_lookup(components, CHAT_KEY_TOPIC);

  if(g_hash_table_lookup(components, CHAT_KEY_IS_PLACE)) {
    /* use place service */
    struct mwServicePlace *srvc;
    struct mwPlace *place = NULL;

    srvc = pd->srvc_place;
    place = mwPlace_new(srvc, c, t);
    mwPlace_open(place);

  } else {
    /* use conference service */
    struct mwServiceConference *srvc;
    struct mwConference *conf = NULL;

    srvc = pd->srvc_conf;
    if(c) conf = conf_find(srvc, c);

    if(conf) {
      DEBUG_INFO("accepting conference invitation\n");
      mwConference_accept(conf);

    } else {
      DEBUG_INFO("creating new conference\n");
      conf = mwConference_new(srvc, t);
      mwConference_open(conf);
    }
  }
}


static void mw_prpl_reject_chat(PurpleConnection *gc,
				GHashTable *components) {

  struct mwPurplePluginData *pd;
  struct mwServiceConference *srvc;
  char *c;

  pd = gc->proto_data;
  srvc = pd->srvc_conf;

  if(g_hash_table_lookup(components, CHAT_KEY_IS_PLACE)) {
    ; /* nothing needs doing */

  } else {
    /* reject conference */
    c = g_hash_table_lookup(components, CHAT_KEY_NAME);
    if(c) {
      struct mwConference *conf = conf_find(srvc, c);
      if(conf) mwConference_reject(conf, ERR_SUCCESS, "Declined");
    }
  }
}


static char *mw_prpl_get_chat_name(GHashTable *components) {
  return g_hash_table_lookup(components, CHAT_KEY_NAME);
}


static void mw_prpl_chat_invite(PurpleConnection *gc,
				int id,
				const char *invitation,
				const char *who) {

  struct mwPurplePluginData *pd;
  struct mwConference *conf;
  struct mwPlace *place;
  struct mwIdBlock idb = { (char *) who, NULL };

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  conf = ID_TO_CONF(pd, id);

  if(conf) {
    mwConference_invite(conf, &idb, invitation);
    return;
  }

  place = ID_TO_PLACE(pd, id);
  g_return_if_fail(place != NULL);

  /* @todo: use the IM service for invitation */
  mwPlace_legacyInvite(place, &idb, invitation);
}


static void mw_prpl_chat_leave(PurpleConnection *gc,
			       int id) {

  struct mwPurplePluginData *pd;
  struct mwConference *conf;

  pd = gc->proto_data;

  g_return_if_fail(pd != NULL);
  conf = ID_TO_CONF(pd, id);

  if(conf) {
    mwConference_destroy(conf, ERR_SUCCESS, "Leaving");

  } else {
    struct mwPlace *place = ID_TO_PLACE(pd, id);
    g_return_if_fail(place != NULL);

    mwPlace_destroy(place, ERR_SUCCESS);
  }
}


static void mw_prpl_chat_whisper(PurpleConnection *gc,
				 int id,
				 const char *who,
				 const char *message) {

  mw_prpl_send_im(gc, who, message, 0);
}


static int mw_prpl_chat_send(PurpleConnection *gc,
			     int id,
			     const char *message,
			     PurpleMessageFlags flags) {

  struct mwPurplePluginData *pd;
  struct mwConference *conf;
  char *msg;
  int ret;

  pd = gc->proto_data;

  g_return_val_if_fail(pd != NULL, 0);
  conf = ID_TO_CONF(pd, id);

  msg = purple_markup_strip_html(message);

  if(conf) {
    ret = ! mwConference_sendText(conf, msg);

  } else {
    struct mwPlace *place = ID_TO_PLACE(pd, id);
    g_return_val_if_fail(place != NULL, 0);

    ret = ! mwPlace_sendText(place, msg);
  }

  g_free(msg);
  return ret;
}


static void mw_prpl_keepalive(PurpleConnection *gc) {
  struct mwSession *session;

  g_return_if_fail(gc != NULL);

  session = gc_to_session(gc);
  g_return_if_fail(session != NULL);

  mwSession_sendKeepalive(session);
}


static void mw_prpl_alias_buddy(PurpleConnection *gc,
				const char *who,
				const char *alias) {

  struct mwPurplePluginData *pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  /* it's a change to the buddy list, so we've gotta reflect that in
     the server copy */

  blist_schedule(pd);
}


static void mw_prpl_group_buddy(PurpleConnection *gc,
				const char *who,
				const char *old_group,
				const char *new_group) {

  struct mwAwareIdBlock idb = { mwAware_USER, (char *) who, NULL };
  GList *gl = g_list_prepend(NULL, &idb);

  struct mwPurplePluginData *pd = gc->proto_data;
  PurpleGroup *group;
  struct mwAwareList *list;

  /* add who to new_group's aware list */
  group = purple_find_group(new_group);
  list = list_ensure(pd, group);
  mwAwareList_addAware(list, gl);

  /* remove who from old_group's aware list */
  group = purple_find_group(old_group);
  list = list_ensure(pd, group);
  mwAwareList_removeAware(list, gl);

  g_list_free(gl);

  /* schedule the changes to be saved */
  blist_schedule(pd);
}


static void mw_prpl_rename_group(PurpleConnection *gc,
				 const char *old,
				 PurpleGroup *group,
				 GList *buddies) {

  struct mwPurplePluginData *pd = gc->proto_data;
  g_return_if_fail(pd != NULL);

  /* it's a change in the buddy list, so we've gotta reflect that in
     the server copy. Also, having this function should prevent all
     those buddies from being removed and re-added. We don't really
     give a crap what the group is named in Purple other than to record
     that as the group name/alias */

  blist_schedule(pd);
}


static void mw_prpl_buddy_free(PurpleBuddy *buddy) {
  /* I don't think we have any cleanup for buddies yet */
  ;
}


static void mw_prpl_convo_closed(PurpleConnection *gc, const char *who) {
  struct mwPurplePluginData *pd = gc->proto_data;
  struct mwServiceIm *srvc;
  struct mwConversation *conv;
  struct mwIdBlock idb = { (char *) who, NULL };

  g_return_if_fail(pd != NULL);

  srvc = pd->srvc_im;
  g_return_if_fail(srvc != NULL);

  conv = mwServiceIm_findConversation(srvc, &idb);
  if(! conv) return;

  if(mwConversation_isOpen(conv))
    mwConversation_free(conv);
}


static const char *mw_prpl_normalize(const PurpleAccount *account,
				     const char *id) {

  /* code elsewhere assumes that the return value points to different
     memory than the passed value, but it won't free the normalized
     data. wtf? */

  static char buf[BUF_LEN];
  g_strlcpy(buf, id, sizeof(buf));
  return buf;
}


static void mw_prpl_remove_group(PurpleConnection *gc, PurpleGroup *group) {
  struct mwPurplePluginData *pd;
  struct mwAwareList *list;

  pd = gc->proto_data;
  g_return_if_fail(pd != NULL);
  g_return_if_fail(pd->group_list_map != NULL);

  list = g_hash_table_lookup(pd->group_list_map, group);

  if(list) {
    g_hash_table_remove(pd->group_list_map, list);
    g_hash_table_remove(pd->group_list_map, group);
    mwAwareList_free(list);

    blist_schedule(pd);
  }
}


static gboolean mw_prpl_can_receive_file(PurpleConnection *gc,
					 const char *who) {
  struct mwPurplePluginData *pd;
  struct mwServiceAware *srvc;
  PurpleAccount *acct;

  g_return_val_if_fail(gc != NULL, FALSE);

  pd = gc->proto_data;
  g_return_val_if_fail(pd != NULL, FALSE);

  srvc = pd->srvc_aware;
  g_return_val_if_fail(srvc != NULL, FALSE);

  acct = purple_connection_get_account(gc);
  g_return_val_if_fail(acct != NULL, FALSE);

  return purple_find_buddy(acct, who) &&
    user_supports(srvc, who, mwAttribute_FILE_TRANSFER);
}


static void ft_outgoing_init(PurpleXfer *xfer) {
  PurpleAccount *acct;
  PurpleConnection *gc;

  struct mwPurplePluginData *pd;
  struct mwServiceFileTransfer *srvc;
  struct mwFileTransfer *ft;

  const char *filename;
  gsize filesize;
  FILE *fp;

  struct mwIdBlock idb = { NULL, NULL };

  DEBUG_INFO("ft_outgoing_init\n");

  acct = purple_xfer_get_account(xfer);
  gc = purple_account_get_connection(acct);
  pd = gc->proto_data;
  srvc = pd->srvc_ft;

  filename = purple_xfer_get_local_filename(xfer);
  filesize = purple_xfer_get_size(xfer);
  idb.user = xfer->who;

  purple_xfer_update_progress(xfer);

  /* test that we can actually send the file */
  fp = g_fopen(filename, "rb");
  if(! fp) {
    char *msg = g_strdup_printf(_("Error reading file %s: \n%s\n"),
				filename, g_strerror(errno));
    purple_xfer_error(purple_xfer_get_type(xfer), acct, xfer->who, msg);
    g_free(msg);
    return;
  }
  fclose(fp);

  {
    char *tmp = strrchr(filename, G_DIR_SEPARATOR);
    if(tmp++) filename = tmp;
  }

  ft = mwFileTransfer_new(srvc, &idb, NULL, filename, filesize);

  purple_xfer_ref(xfer);
  mwFileTransfer_setClientData(ft, xfer, (GDestroyNotify) purple_xfer_unref);
  xfer->data = ft;

  mwFileTransfer_offer(ft);
}


static void ft_outgoing_cancel(PurpleXfer *xfer) {
  struct mwFileTransfer *ft = xfer->data;

  DEBUG_INFO("ft_outgoing_cancel called\n");

  if(ft) mwFileTransfer_cancel(ft);
}


static PurpleXfer *mw_prpl_new_xfer(PurpleConnection *gc, const char *who) {
  PurpleAccount *acct;
  PurpleXfer *xfer;

  acct = purple_connection_get_account(gc);

  xfer = purple_xfer_new(acct, PURPLE_XFER_SEND, who);
  if (xfer)
  {
    purple_xfer_set_init_fnc(xfer, ft_outgoing_init);
    purple_xfer_set_cancel_send_fnc(xfer, ft_outgoing_cancel);
  }

  return xfer;
}

static void mw_prpl_send_file(PurpleConnection *gc,
			      const char *who, const char *file) {

  PurpleXfer *xfer = mw_prpl_new_xfer(gc, who);

  if(file) {
    DEBUG_INFO("file != NULL\n");
    purple_xfer_request_accepted(xfer, file);

  } else {
    DEBUG_INFO("file == NULL\n");
    purple_xfer_request(xfer);
  }
}


static PurplePluginProtocolInfo mw_prpl_info = {
  OPT_PROTO_IM_IMAGE,
  NULL, /*< set in mw_plugin_init */
  NULL, /*< set in mw_plugin_init */
  NO_BUDDY_ICONS,
  mw_prpl_list_icon,
  mw_prpl_list_emblem,
  mw_prpl_status_text,
  mw_prpl_tooltip_text,
  mw_prpl_status_types,
  mw_prpl_blist_node_menu,
  mw_prpl_chat_info,
  mw_prpl_chat_info_defaults,
  mw_prpl_login,
  mw_prpl_close,
  mw_prpl_send_im,
  NULL,
  mw_prpl_send_typing,
  mw_prpl_get_info,
  mw_prpl_set_status,
  mw_prpl_set_idle,
  NULL,
  mw_prpl_add_buddy,
  mw_prpl_add_buddies,
  mw_prpl_remove_buddy,
  NULL,
  mw_prpl_add_permit,
  mw_prpl_add_deny,
  mw_prpl_rem_permit,
  mw_prpl_rem_deny,
  mw_prpl_set_permit_deny,
  mw_prpl_join_chat,
  mw_prpl_reject_chat,
  mw_prpl_get_chat_name,
  mw_prpl_chat_invite,
  mw_prpl_chat_leave,
  mw_prpl_chat_whisper,
  mw_prpl_chat_send,
  mw_prpl_keepalive,
  NULL,
  NULL,
  NULL,
  mw_prpl_alias_buddy,
  mw_prpl_group_buddy,
  mw_prpl_rename_group,
  mw_prpl_buddy_free,
  mw_prpl_convo_closed,
  mw_prpl_normalize,
  NULL,
  mw_prpl_remove_group,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  mw_prpl_can_receive_file,
  mw_prpl_send_file,
  mw_prpl_new_xfer,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  sizeof(PurplePluginProtocolInfo),
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};


static PurplePluginPrefFrame *
mw_plugin_get_plugin_pref_frame(PurplePlugin *plugin) {
  PurplePluginPrefFrame *frame;
  PurplePluginPref *pref;

  frame = purple_plugin_pref_frame_new();

  pref = purple_plugin_pref_new_with_label(_("Remotely Stored Buddy List"));
  purple_plugin_pref_frame_add(frame, pref);


  pref = purple_plugin_pref_new_with_name(MW_PRPL_OPT_BLIST_ACTION);
  purple_plugin_pref_set_label(pref, _("Buddy List Storage Mode"));

  purple_plugin_pref_set_type(pref, PURPLE_PLUGIN_PREF_CHOICE);
  purple_plugin_pref_add_choice(pref, _("Local Buddy List Only"),
			      GINT_TO_POINTER(blist_choice_LOCAL));
  purple_plugin_pref_add_choice(pref, _("Merge List from Server"),
			      GINT_TO_POINTER(blist_choice_MERGE));
  purple_plugin_pref_add_choice(pref, _("Merge and Save List to Server"),
			      GINT_TO_POINTER(blist_choice_STORE));
  purple_plugin_pref_add_choice(pref, _("Synchronize List with Server"),
			      GINT_TO_POINTER(blist_choice_SYNCH));

  purple_plugin_pref_frame_add(frame, pref);

  return frame;
}


static PurplePluginUiInfo mw_plugin_ui_info = {
  mw_plugin_get_plugin_pref_frame,
  0,    /* page_num */
  NULL, /* frame */
  NULL,
  NULL,
  NULL,
  NULL
};


static void st_import_action_cb(PurpleConnection *gc, char *filename) {
  struct mwSametimeList *l;

  FILE *file;
  char buf[BUF_LEN];
  size_t len;

  GString *str;

  file = g_fopen(filename, "r");
  g_return_if_fail(file != NULL);

  str = g_string_new(NULL);
  while( (len = fread(buf, 1, BUF_LEN, file)) ) {
    g_string_append_len(str, buf, len);
  }

  fclose(file);

  l = mwSametimeList_load(str->str);
  g_string_free(str, TRUE);

  blist_merge(gc, l);
  mwSametimeList_free(l);
}


/** prompts for a file to import blist from */
static void st_import_action(PurplePluginAction *act) {
  PurpleConnection *gc;
  PurpleAccount *account;
  char *title;

  gc = act->context;
  account = purple_connection_get_account(gc);
  title = g_strdup_printf(_("Import Sametime List for Account %s"),
			  purple_account_get_username(account));

  purple_request_file(gc, title, NULL, FALSE,
		    G_CALLBACK(st_import_action_cb), NULL,
		    account, NULL, NULL,
		    gc);

  g_free(title);
}


static void st_export_action_cb(PurpleConnection *gc, char *filename) {
  struct mwSametimeList *l;
  char *str;
  FILE *file;

  file = g_fopen(filename, "w");
  g_return_if_fail(file != NULL);

  l = mwSametimeList_new();
  blist_export(gc, l);
  str = mwSametimeList_store(l);
  mwSametimeList_free(l);

  fprintf(file, "%s", str);
  fclose(file);

  g_free(str);
}


/** prompts for a file to export blist to */
static void st_export_action(PurplePluginAction *act) {
  PurpleConnection *gc;
  PurpleAccount *account;
  char *title;

  gc = act->context;
  account = purple_connection_get_account(gc);
  title = g_strdup_printf(_("Export Sametime List for Account %s"),
			  purple_account_get_username(account));

  purple_request_file(gc, title, NULL, TRUE,
		    G_CALLBACK(st_export_action_cb), NULL,
			account, NULL, NULL,
		    gc);

  g_free(title);
}


static void remote_group_multi_cleanup(gpointer ignore,
				       PurpleRequestFields *fields) {

  PurpleRequestField *f;
  GList *l;

  f = purple_request_fields_get_field(fields, "group");
  l = purple_request_field_list_get_items(f);

  for(; l; l = l->next) {
    const char *i = l->data;
    struct named_id *res;

    res = purple_request_field_list_get_data(f, i);

    g_free(res->id);
    g_free(res->name);
    g_free(res);
  }
}


static void remote_group_done(struct mwPurplePluginData *pd,
			      const char *id, const char *name) {
  PurpleConnection *gc;
  PurpleAccount *acct;
  PurpleGroup *group;
  PurpleBlistNode *gn;
  const char *owner;

  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  acct = purple_connection_get_account(gc);

  /* collision checking */
  group = purple_find_group(name);
  if(group) {
    const char *msgA;
    const char *msgB;
    char *msg;

    msgA = _("Unable to add group: group exists");
    msgB = _("A group named '%s' already exists in your buddy list.");
    msg = g_strdup_printf(msgB, name);

    purple_notify_error(gc, _("Unable to add group"), msgA, msg);

    g_free(msg);
    return;
  }

  group = purple_group_new(name);
  gn = (PurpleBlistNode *) group;

  owner = purple_account_get_username(acct);

  purple_blist_node_set_string(gn, GROUP_KEY_NAME, id);
  purple_blist_node_set_int(gn, GROUP_KEY_TYPE, mwSametimeGroup_DYNAMIC);
  purple_blist_node_set_string(gn, GROUP_KEY_OWNER, owner);
  purple_blist_add_group(group, NULL);

  group_add(pd, group);
  blist_schedule(pd);
}


static void remote_group_multi_cb(struct mwPurplePluginData *pd,
				  PurpleRequestFields *fields) {
  PurpleRequestField *f;
  GList *l;

  f = purple_request_fields_get_field(fields, "group");
  l = purple_request_field_list_get_selected(f);

  if(l) {
    const char *i = l->data;
    struct named_id *res;

    res = purple_request_field_list_get_data(f, i);
    remote_group_done(pd, res->id, res->name);
  }

  remote_group_multi_cleanup(NULL, fields);
}


static void remote_group_multi(struct mwResolveResult *result,
			       struct mwPurplePluginData *pd) {

  PurpleRequestFields *fields;
  PurpleRequestFieldGroup *g;
  PurpleRequestField *f;
  GList *l;
  const char *msgA;
  const char *msgB;
  char *msg;

  PurpleConnection *gc = pd->gc;

  fields = purple_request_fields_new();

  g = purple_request_field_group_new(NULL);
  purple_request_fields_add_group(fields, g);

  f = purple_request_field_list_new("group", _("Possible Matches"));
  purple_request_field_list_set_multi_select(f, FALSE);
  purple_request_field_set_required(f, TRUE);

  for(l = result->matches; l; l = l->next) {
    struct mwResolveMatch *match = l->data;
    struct named_id *res = g_new0(struct named_id, 1);

    res->id = g_strdup(match->id);
    res->name = g_strdup(match->name);

    purple_request_field_list_add_icon(f, res->name, NULL, res);
  }

  purple_request_field_group_add_field(g, f);

  msgA = _("Notes Address Book group results");
  msgB = _("The identifier '%s' may possibly refer to any of the following"
	  " Notes Address Book groups. Please select the correct group from"
	  " the list below to add it to your buddy list.");
  msg = g_strdup_printf(msgB, result->name);

  purple_request_fields(gc, _("Select Notes Address Book"),
		      msgA, msg, fields,
		      _("Add Group"), G_CALLBACK(remote_group_multi_cb),
		      _("Cancel"), G_CALLBACK(remote_group_multi_cleanup),
			  purple_connection_get_account(gc), result->name, NULL,
		      pd);

  g_free(msg);
}


static void remote_group_resolved(struct mwServiceResolve *srvc,
				  guint32 id, guint32 code, GList *results,
				  gpointer b) {

  struct mwResolveResult *res = NULL;
  struct mwSession *session;
  struct mwPurplePluginData *pd;
  PurpleConnection *gc;

  session = mwService_getSession(MW_SERVICE(srvc));
  g_return_if_fail(session != NULL);

  pd = mwSession_getClientData(session);
  g_return_if_fail(pd != NULL);

  gc = pd->gc;
  g_return_if_fail(gc != NULL);

  if(!code && results) {
    res = results->data;

    if(res->matches) {
      remote_group_multi(res, pd);
      return;
    }
  }

  if(res && res->name) {
    const char *msgA;
    const char *msgB;
    char *msg;

    msgA = _("Unable to add group: group not found");

    msgB = _("The identifier '%s' did not match any Notes Address Book"
	    " groups in your Sametime community.");
    msg = g_strdup_printf(msgB, res->name);

    purple_notify_error(gc, _("Unable to add group"), msgA, msg);

    g_free(msg);
  }
}


static void remote_group_action_cb(PurpleConnection *gc, const char *name) {
  struct mwPurplePluginData *pd;
  struct mwServiceResolve *srvc;
  GList *query;
  enum mwResolveFlag flags;
  guint32 req;

  pd = gc->proto_data;
  srvc = pd->srvc_resolve;

  query = g_list_prepend(NULL, (char *) name);
  flags = mwResolveFlag_FIRST | mwResolveFlag_GROUPS;

  req = mwServiceResolve_resolve(srvc, query, flags, remote_group_resolved,
				 NULL, NULL);
  g_list_free(query);

  if(req == SEARCH_ERROR) {
    /** @todo display error */
  }
}


static void remote_group_action(PurplePluginAction *act) {
  PurpleConnection *gc;
  const char *msgA;
  const char *msgB;

  gc = act->context;

  msgA = _("Notes Address Book Group");
  msgB = _("Enter the name of a Notes Address Book group in the field below"
	  " to add the group and its members to your buddy list.");

  purple_request_input(gc, _("Add Group"), msgA, msgB, NULL,
		     FALSE, FALSE, NULL,
		     _("Add"), G_CALLBACK(remote_group_action_cb),
		     _("Cancel"), NULL,
			 purple_connection_get_account(gc), NULL, NULL,
		     gc);
}


static void search_notify(struct mwResolveResult *result,
			  PurpleConnection *gc) {
  GList *l;
  const char *msgA;
  const char *msgB;
  char *msg1;
  char *msg2;

  PurpleNotifySearchResults *sres;
  PurpleNotifySearchColumn *scol;

  sres = purple_notify_searchresults_new();

  scol = purple_notify_searchresults_column_new(_("User Name"));
  purple_notify_searchresults_column_add(sres, scol);

  scol = purple_notify_searchresults_column_new(_("Sametime ID"));
  purple_notify_searchresults_column_add(sres, scol);

  purple_notify_searchresults_button_add(sres, PURPLE_NOTIFY_BUTTON_IM,
				       notify_im);

  purple_notify_searchresults_button_add(sres, PURPLE_NOTIFY_BUTTON_ADD,
				       notify_add);

  for(l = result->matches; l; l = l->next) {
    struct mwResolveMatch *match = l->data;
    GList *row = NULL;

    if(!match->id || !match->name)
      continue;

    row = g_list_append(row, g_strdup(match->name));
    row = g_list_append(row, g_strdup(match->id));
    purple_notify_searchresults_row_add(sres, row);
  }

  msgA = _("Search results for '%s'");
  msgB = _("The identifier '%s' may possibly refer to any of the following"
	   " users. You may add these users to your buddy list or send them"
	   " messages with the action buttons below.");

  msg1 = g_strdup_printf(msgA, result->name);
  msg2 = g_strdup_printf(msgB, result->name);

  purple_notify_searchresults(gc, _("Search Results"),
			    msg1, msg2, sres, notify_close, NULL);

  g_free(msg1);
  g_free(msg2);
}


static void search_resolved(struct mwServiceResolve *srvc,
			    guint32 id, guint32 code, GList *results,
			    gpointer b) {

  PurpleConnection *gc = b;
  struct mwResolveResult *res = NULL;

  if(results) res = results->data;

  if(!code && res && res->matches) {
    search_notify(res, gc);

  } else {
    const char *msgA;
    const char *msgB;
    char *msg;

    msgA = _("No matches");
    msgB = _("The identifier '%s' did not match any users in your"
	     " Sametime community.");
    msg = g_strdup_printf(msgB, (res && res->name) ? NSTR(res->name) : "");

    purple_notify_error(gc, _("No Matches"), msgA, msg);

    g_free(msg);
  }
}


static void search_action_cb(PurpleConnection *gc, const char *name) {
  struct mwPurplePluginData *pd;
  struct mwServiceResolve *srvc;
  GList *query;
  enum mwResolveFlag flags;
  guint32 req;

  pd = gc->proto_data;
  srvc = pd->srvc_resolve;

  query = g_list_prepend(NULL, (char *) name);
  flags = mwResolveFlag_FIRST | mwResolveFlag_USERS;

  req = mwServiceResolve_resolve(srvc, query, flags, search_resolved,
				 gc, NULL);
  g_list_free(query);

  if(req == SEARCH_ERROR) {
    /** @todo display error */
  }
}


static void search_action(PurplePluginAction *act) {
  PurpleConnection *gc;
  const char *msgA;
  const char *msgB;

  gc = act->context;

  msgA = _("Search for a user");
  msgB = _("Enter a name or partial ID in the field below to search"
	   " for matching users in your Sametime community.");

  purple_request_input(gc, _("User Search"), msgA, msgB, NULL,
		     FALSE, FALSE, NULL,
		     _("Search"), G_CALLBACK(search_action_cb),
		     _("Cancel"), NULL,
			 purple_connection_get_account(gc), NULL, NULL,
			 gc);
}


static GList *mw_plugin_actions(PurplePlugin *plugin, gpointer context) {
  PurplePluginAction *act;
  GList *l = NULL;

  act = purple_plugin_action_new(_("Import Sametime List..."),
			       st_import_action);
  l = g_list_append(l, act);

  act = purple_plugin_action_new(_("Export Sametime List..."),
			       st_export_action);
  l = g_list_append(l, act);

  act = purple_plugin_action_new(_("Add Notes Address Book Group..."),
			       remote_group_action);
  l = g_list_append(l, act);

  act = purple_plugin_action_new(_("User Search..."),
			       search_action);
  l = g_list_append(l, act);

  return l;
}


static gboolean mw_plugin_load(PurplePlugin *plugin) {
  return TRUE;
}


static gboolean mw_plugin_unload(PurplePlugin *plugin) {
  return TRUE;
}


static void mw_plugin_destroy(PurplePlugin *plugin) {
  g_log_remove_handler(G_LOG_DOMAIN, log_handler[0]);
  g_log_remove_handler("meanwhile", log_handler[1]);
}

static PurplePluginInfo mw_plugin_info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */

	PLUGIN_ID,                                        /**< id             */
	PLUGIN_NAME,                                      /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	PLUGIN_SUMMARY,                                   /**< summary        */
	PLUGIN_DESC,                                      /**<  description    */
	PLUGIN_AUTHOR,                                    /**< author         */
	PLUGIN_HOMEPAGE,                                  /**< homepage       */

	mw_plugin_load,                                   /**< load           */
	mw_plugin_unload,                                 /**< unload         */
	mw_plugin_destroy,                                /**< destroy        */

	NULL,                                             /**< ui_info        */
	&mw_prpl_info,                                    /**< extra_info     */
	&mw_plugin_ui_info,                               /**< prefs_info     */
	mw_plugin_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};


static void mw_log_handler(const gchar *domain, GLogLevelFlags flags,
			   const gchar *msg, gpointer data) {

  if(! (msg && *msg)) return;

  /* handle g_log requests via purple's built-in debug logging */
  if(flags & G_LOG_LEVEL_ERROR) {
    purple_debug_error(domain, "%s\n", msg);

  } else if(flags & G_LOG_LEVEL_WARNING) {
    purple_debug_warning(domain, "%s\n", msg);

  } else {
    purple_debug_info(domain, "%s\n", msg);
  }
}


static void mw_plugin_init(PurplePlugin *plugin) {
  PurpleAccountUserSplit *split;
  PurpleAccountOption *opt;
  GList *l = NULL;

  GLogLevelFlags logflags =
    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;

  /* set up the preferences */
  purple_prefs_add_none(MW_PRPL_OPT_BASE);
  purple_prefs_add_int(MW_PRPL_OPT_BLIST_ACTION, BLIST_CHOICE_DEFAULT);

  /* set up account ID as user:server */
  split = purple_account_user_split_new(_("Server"),
                                        MW_PLUGIN_DEFAULT_HOST, ':');
  mw_prpl_info.user_splits = g_list_append(mw_prpl_info.user_splits, split);

  /* remove dead preferences */
  purple_prefs_remove(MW_PRPL_OPT_PSYCHIC);
  purple_prefs_remove(MW_PRPL_OPT_SAVE_DYNAMIC);

  /* port to connect to */
  opt = purple_account_option_int_new(_("Port"), MW_KEY_PORT,
				    MW_PLUGIN_DEFAULT_PORT);
  l = g_list_append(l, opt);

  { /* copy the old force login setting from prefs if it's
       there. Don't delete the preference, since there may be more
       than one account that wants to check for it. */
    gboolean b = FALSE;
    const char *label = _("Force login (ignore server redirects)");

    if(purple_prefs_exists(MW_PRPL_OPT_FORCE_LOGIN))
      b = purple_prefs_get_bool(MW_PRPL_OPT_FORCE_LOGIN);

    opt = purple_account_option_bool_new(label, MW_KEY_FORCE, b);
    l = g_list_append(l, opt);
  }

  /* pretend to be Sametime Connect */
  opt = purple_account_option_bool_new(_("Hide client identity"),
				     MW_KEY_FAKE_IT, FALSE);
  l = g_list_append(l, opt);

  mw_prpl_info.protocol_options = l;
  l = NULL;

  /* forward all our g_log messages to purple. Generally all the logging
     calls are using purple_log directly, but the g_return macros will
     get caught here */
  log_handler[0] = g_log_set_handler(G_LOG_DOMAIN, logflags,
				     mw_log_handler, NULL);

  /* redirect meanwhile's logging to purple's */
  log_handler[1] = g_log_set_handler("meanwhile", logflags,
				     mw_log_handler, NULL);
}


PURPLE_INIT_PLUGIN(sametime, mw_plugin_init, mw_plugin_info);
/* The End. */

