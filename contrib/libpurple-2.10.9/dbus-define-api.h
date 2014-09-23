#error "This is file is not a valid C code"

/* This file contains some of the macros from other header files as
   function declarations.  This does not make sense in C, but it
   provides type information for the dbus-analyze-functions.py
   program, which makes these macros callable by DBUS.  */

/* blist.h */
gboolean PURPLE_BLIST_NODE_IS_CHAT(PurpleBlistNode *node);
gboolean PURPLE_BLIST_NODE_IS_BUDDY(PurpleBlistNode *node);
gboolean PURPLE_BLIST_NODE_IS_CONTACT(PurpleBlistNode *node);
gboolean PURPLE_BLIST_NODE_IS_GROUP(PurpleBlistNode *node);
gboolean PURPLE_BUDDY_IS_ONLINE(PurpleBuddy *buddy);
gboolean PURPLE_BLIST_NODE_HAS_FLAG(PurpleBlistNode *node, int flags);
gboolean PURPLE_BLIST_NODE_SHOULD_SAVE(PurpleBlistNode *node);

/* connection.h */
gboolean PURPLE_CONNECTION_IS_CONNECTED(PurpleConnection *connection);
gboolean PURPLE_CONNECTION_IS_VALID(PurpleConnection *connection);

/* conversation.h */
PurpleConvIm *PURPLE_CONV_IM(const PurpleConversation *conversation);
PurpleConvIm *PURPLE_CONV_CHAT(const PurpleConversation *conversation);


