/**
 * (n+1)Sec Multiparty Off-the-Record Messaging library
 * Copyright (C) 2016, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "ui.h"

#include "src/interface.h"
#include "src/room.h"

#include <unistd.h>


#define CUSTOM_USER_DIRECTORY "/tmp/test_user"
#define CUSTOM_PLUGIN_PATH ""
#define PLUGIN_SAVE_PREF "/tmp/test_client/plugins/saved"
#define UI_ID "jabberite"



/*
 * START copied from libpurple example
 */

#define PURPLE_GLIB_READ_COND (G_IO_IN | G_IO_HUP | G_IO_ERR)
#define PURPLE_GLIB_WRITE_COND (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)

typedef struct _PurpleGLibIOClosure {
	PurpleInputFunction function;
	guint result;
	gpointer data;
} PurpleGLibIOClosure;

void purple_glib_io_destroy(gpointer data)
{
	g_free(data);
}

gboolean purple_glib_io_invoke(GIOChannel* source, GIOCondition condition, gpointer data)
{
	PurpleGLibIOClosure* closure = static_cast<PurpleGLibIOClosure*>(data);
	int purple_cond = 0;
	
	if (condition & PURPLE_GLIB_READ_COND)
		purple_cond |= PURPLE_INPUT_READ;
	if (condition & PURPLE_GLIB_WRITE_COND)
		purple_cond |= PURPLE_INPUT_WRITE;
	
	closure->function(closure->data, g_io_channel_unix_get_fd(source), static_cast<PurpleInputCondition>(purple_cond));
	
	return TRUE;
}

guint glib_input_add(gint fd, PurpleInputCondition condition, PurpleInputFunction function, gpointer data)
{
	PurpleGLibIOClosure* closure = g_new0(PurpleGLibIOClosure, 1);
	GIOChannel* channel;
	int cond = 0;
	
	closure->function = function;
	closure->data = data;
	
	if (condition & PURPLE_INPUT_READ)
		cond |= PURPLE_GLIB_READ_COND;
	if (condition & PURPLE_INPUT_WRITE)
		cond |= PURPLE_GLIB_WRITE_COND;

#if defined _WIN32 && !defined WINPIDGIN_USE_GLIB_IO_CHANNEL
	channel = wpurple_g_io_channel_win32_new_socket(fd);
#else
	channel = g_io_channel_unix_new(fd);
	#endif
	closure->result = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, static_cast<GIOCondition>(cond),
	                                      purple_glib_io_invoke, closure, purple_glib_io_destroy);
	
	g_io_channel_unref(channel);
	return closure->result;
}

PurpleEventLoopUiOps glib_eventloops = 
{
	g_timeout_add,
	g_source_remove,
	glib_input_add,
	g_source_remove,
	NULL,
#if GLIB_CHECK_VERSION(2, 14, 0)
	g_timeout_add_seconds,
#else
	NULL,
#endif
	NULL,
	NULL,
	NULL
};

/*
 * END copied from libpurple example
 */

void setup_purple(void)
{
	purple_util_set_user_dir(CUSTOM_USER_DIRECTORY);
	purple_debug_set_enabled(FALSE);
	purple_eventloop_set_ui_ops(&glib_eventloops);
	purple_plugins_add_search_path(CUSTOM_PLUGIN_PATH);
	
	if (!purple_core_init(UI_ID)) {
		fprintf(stderr, "initializing libpurple failed\n");
		abort();
	}
	
	purple_set_blist(purple_blist_new());
	purple_blist_load();
	purple_prefs_load();
	purple_plugins_load_saved(PLUGIN_SAVE_PREF);
	purple_pounces_load();
}



static void process_connection_error(PurpleConnection*, PurpleConnectionError, const gchar*, void *m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	jabberite->connection_error();
}

static void process_signed_on(PurpleConnection* connection, void *m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	jabberite->connection = connection;
	
	GHashTable* components = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(components, strdup("room"), strdup(jabberite->room_name.c_str()));
	g_hash_table_insert(components, strdup("server"), strdup(jabberite->server.c_str()));
	g_hash_table_insert(components, strdup("handle"), strdup(jabberite->nickname.c_str()));
	serv_join_chat(connection, components);
}

static void process_chat_joined(PurpleConversation* conversation, void* m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	jabberite->conv = conversation;
	
	jabberite->room->connect();
}

static void process_chat_join_failed(PurpleConnection*, GHashTable*, void* m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	jabberite->connection_error();
}

static void process_chat_buddy_left(PurpleConversation*, const char* name, const char*, void* m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	jabberite->room->user_left(std::string(name));
}

static void process_received_chat(PurpleAccount*, char* sender, char* message, PurpleConversation*, int flags, void* m)
{
	Jabberite* jabberite = reinterpret_cast<Jabberite*>(m);
	
	// skip historic messages
	if (!(flags & PURPLE_MESSAGE_DELAYED)) {
		jabberite->room->message_received(std::string(sender), std::string(message));
	}
}

static void setup_purple_callbacks(Jabberite* jabberite)
{
	static int handle;
	void* conn_handle = purple_connections_get_handle();
	void* conv_handle = purple_conversations_get_handle();
	
	purple_signal_connect(conn_handle, "connection-error", &handle, PURPLE_CALLBACK(process_connection_error), jabberite);
	purple_signal_connect(conn_handle, "signed-on", &handle, PURPLE_CALLBACK(process_signed_on), jabberite);
	purple_signal_connect(conv_handle, "chat-joined", &handle, PURPLE_CALLBACK(process_chat_joined), jabberite);
	purple_signal_connect(conv_handle, "chat-join-failed", &handle, PURPLE_CALLBACK(process_chat_join_failed), jabberite);
	purple_signal_connect(conv_handle, "chat-buddy-left", &handle, PURPLE_CALLBACK(process_chat_buddy_left), jabberite);
	purple_signal_connect(conv_handle, "received-chat-msg", &handle, PURPLE_CALLBACK(process_received_chat), jabberite);
}




class JabberiteConversationInterface final : public np1sec::ConversationInterface
{
	public:
	JabberiteConversationInterface(Jabberite* jabberite_, np1sec::Conversation* conversation_): jabberite(jabberite_), conversation(conversation_) {}
	void user_invited(const std::string& inviter, const std::string& invitee);
	void invitation_cancelled(const std::string& inviter, const std::string& invitee);
	void user_authenticated(const std::string& username, const np1sec::PublicKey& public_key);
	void user_authentication_failed(const std::string& username);
	void user_joining(const std::string& username);
	void user_left(const std::string& username);
	void votekick_registered(const std::string& kicker, const std::string& victim, bool kicked);
	
	void user_joined(const std::string& username);
	void message_received(const std::string& sender, const std::string& message);
	
	void joining();
	void joined();
	void left();
	
	protected:
	int id() { return jabberite->conversation_id(conversation); }
	
	public:
	Jabberite* jabberite;
	np1sec::Conversation* conversation;
};

void JabberiteConversationInterface::user_invited(const std::string& inviter, const std::string& invitee)
{
	jabberite->user_invited(id(), inviter, invitee);
}

void JabberiteConversationInterface::invitation_cancelled(const std::string& inviter, const std::string& invitee)
{
	jabberite->invitation_cancelled(id(), inviter, invitee);
}

void JabberiteConversationInterface::user_authenticated(const std::string& username, const np1sec::PublicKey& public_key)
{
	jabberite->user_authenticated(id(), username, public_key);
}

void JabberiteConversationInterface::user_authentication_failed(const std::string& username)
{
	jabberite->user_authentication_failed(id(), username);
}

void JabberiteConversationInterface::user_joining(const std::string& username)
{
	jabberite->user_joining(id(), username);
}

void JabberiteConversationInterface::user_left(const std::string& username)
{
	jabberite->user_left(id(), username);
}

void JabberiteConversationInterface::votekick_registered(const std::string& kicker, const std::string& victim, bool kicked)
{
	jabberite->votekick_registered(id(), kicker, victim, kicked);
}

void JabberiteConversationInterface::user_joined(const std::string& username)
{
	jabberite->user_joined(id(), username);
}

void JabberiteConversationInterface::message_received(const std::string& sender, const std::string& message)
{
	jabberite->message_received(id(), sender, message);
}

void JabberiteConversationInterface::joining()
{
	jabberite->joining(id());
}

void JabberiteConversationInterface::joined()
{
	jabberite->joined(id());
}

void JabberiteConversationInterface::left()
{
	jabberite->left(id());
	jabberite->remove_conversation(conversation);
}



class JabberiteRoomInterface : public np1sec::RoomInterface
{
	public:
	JabberiteRoomInterface(Jabberite* jabberite): m_jabberite(jabberite) {}
	void send_message(const std::string& message);
	np1sec::TimerToken* set_timer(uint32_t interval, np1sec::TimerCallback* callback);
	
	void connected();
	void disconnected();
	void user_joined(const std::string& username, const np1sec::PublicKey& public_key);
	void user_left(const std::string& username, const np1sec::PublicKey& public_key);
	np1sec::ConversationInterface* created_conversation(np1sec::Conversation* conversation);
	np1sec::ConversationInterface* invited_to_conversation(np1sec::Conversation* conversation, const std::string& username);
	
	protected:
	Jabberite* m_jabberite;
};

void JabberiteRoomInterface::send_message(const std::string& message)
{
	if (!m_jabberite->frozen) {
		purple_conv_chat_send(PURPLE_CONV_CHAT(m_jabberite->conv), message.c_str());
	}
}

struct JabberiteTimer final : public np1sec::TimerToken
{
	np1sec::TimerCallback* callback;
	guint timer_id;
	
	void unset()
	{
		g_source_remove(timer_id);
		delete this;
	}
};

static gboolean execute_timer(gpointer jabberite_timer)
{
	JabberiteTimer* timer = reinterpret_cast<JabberiteTimer*>(jabberite_timer);
	timer->callback->execute();
	delete timer;
	// returning 0 stops the timer
	return 0;
}

np1sec::TimerToken* JabberiteRoomInterface::set_timer(uint32_t interval, np1sec::TimerCallback* callback)
{
	JabberiteTimer* timer = new JabberiteTimer;
	timer->callback = callback;
	timer->timer_id = g_timeout_add(interval, execute_timer, timer);
	return timer;
}


void JabberiteRoomInterface::connected()
{
	m_jabberite->connected();
}

void JabberiteRoomInterface::disconnected()
{
	m_jabberite->disconnected();
}

void JabberiteRoomInterface::user_joined(const std::string& username, const np1sec::PublicKey& public_key)
{
	m_jabberite->user_joined(username, public_key);
}

void JabberiteRoomInterface::user_left(const std::string& username, const np1sec::PublicKey& public_key)
{
	m_jabberite->user_left(username, public_key);
}

np1sec::ConversationInterface* JabberiteRoomInterface::created_conversation(np1sec::Conversation* conversation)
{
	JabberiteConversationInterface* interface = new JabberiteConversationInterface(m_jabberite, conversation);
	int id = m_jabberite->add_conversation(interface);
	m_jabberite->created_conversation(id, conversation);
	return interface;
}

np1sec::ConversationInterface* JabberiteRoomInterface::invited_to_conversation(np1sec::Conversation* conversation, const std::string& username)
{
	JabberiteConversationInterface* interface = new JabberiteConversationInterface(m_jabberite, conversation);
	int id = m_jabberite->add_conversation(interface);
	m_jabberite->invited_to_conversation(id, conversation, username);
	return interface;
}



Jabberite::Jabberite():
	account(nullptr),
	connection(nullptr),
	conv(nullptr),
	frozen(false),
	room(nullptr)
{
}

void Jabberite::connect()
{
	if (room) {
		room->connect();
	}
}

void Jabberite::disconnect()
{
	if (room) {
		room->disconnect();
	}
}

void Jabberite::create_conversation()
{
	if (room) {
		room->create_conversation();
	}
}

void Jabberite::leave(int conversation_id)
{
	if (room) {
		np1sec::Conversation* c = conversation(conversation_id);
		if (!c) {
			return;
		}
		c->leave(false);
	}
}

void Jabberite::invite(int conversation_id, std::string username)
{
	if (room) {
		std::map<std::string, np1sec::PublicKey> users = room->users();
		if (!users.count(username)) {
			return;
		}
		np1sec::Conversation* c = conversation(conversation_id);
		if (!c) {
			return;
		}
		c->invite(username, users[username]);
	}
}

void Jabberite::join(int conversation_id)
{
	if (room) {
		np1sec::Conversation* c = conversation(conversation_id);
		if (!c) {
			return;
		}
		c->join();
	}
}

void Jabberite::votekick(int conversation_id, std::string username, bool kick)
{
	if (room) {
		np1sec::Conversation* c = conversation(conversation_id);
		if (!c) {
			return;
		}
		c->votekick(username, kick);
	}
}

void Jabberite::send_chat(int conversation_id, std::string message)
{
	if (room) {
		np1sec::Conversation* c = conversation(conversation_id);
		if (!c) {
			return;
		}
		c->send_chat(message);
	}
}

np1sec::Conversation* Jabberite::conversation(int id)
{
	if (id < 0 || (size_t) id >= conversations.size()) {
		return nullptr;
	}
	if (!conversations[id]) {
		return nullptr;
	}
	return conversations[id]->conversation;
}

int Jabberite::conversation_id(np1sec::Conversation* conversation)
{
	for (int i = 0; (size_t)i < conversations.size(); i++) {
		if (conversations[i] && conversations[i]->conversation == conversation) {
			return i;
		}
	}
	return -1;
}

int Jabberite::add_conversation(JabberiteConversationInterface* interface)
{
	int id = conversations.size();
	conversations.push_back(interface);
	return id;
}

int Jabberite::remove_conversation(np1sec::Conversation* conversation)
{
	int id = conversation_id(conversation);
	if (id != -1) {
		if (conversations[id]) {
			delete conversations[id];
			conversations[id] = nullptr;
		}
	}
	return id;
}






void Jabberite::run()
{
	GMainLoop* loop = g_main_loop_new(NULL, FALSE);
	
	setup_purple();
	const char* prpl = NULL;
	for (GList* iter = purple_plugins_get_protocols(); iter; iter = iter->next) {
		PurplePlugin* plugin = static_cast<PurplePlugin*>(iter->data);
		PurplePluginInfo* info = plugin->info;
		if (info && info->name && !strcmp("XMPP", info->name)) {
			prpl = info->id;
			break;
		}
	}
	if (!prpl) {
		fprintf(stderr, "Failed to get protocol.");
		abort();
	}
	
	
	
	JabberiteRoomInterface* interface = new JabberiteRoomInterface(this);
	room = new np1sec::Room(interface, nickname, np1sec::PrivateKey::generate(true));
	
	
	
	account = purple_account_new(username.c_str(), prpl);
	purple_account_set_password(account, password.c_str());
	if (port != -1) {
		purple_account_set_int(account, "port", port);
	}
	
	setup_purple_callbacks(this);
	
	purple_account_set_enabled(account, UI_ID, TRUE);
	purple_savedstatus_activate(purple_savedstatus_new(NULL, PURPLE_STATUS_AVAILABLE));
	
	g_main_loop_run(loop);
}

void Jabberite::print_usage(std::string program_name, std::vector<option> extra_options)
{
	fprintf(stderr, "Usage: %s options [ inputfile ... ]\n", program_name.c_str());
	fprintf(stderr, " -h --help                       Display this usage information.\n"
	                " -a --account    xmpp account    The xmpp account used for login\n"
	                " -p --password   password        The password for the login\n"
	                " -s --server     server name     The conference server\n"
	                " -r --room       room name       The room name to join\n"
	                " -P --port       port number     The port to connect on; defaults to 5222\n"
	);
	
	for (const option& option : extra_options) {
		std::string description = explain_option(option.val);
		std::string parameter = "";
		if (option.has_arg) {
			parameter = explain_parameter(option.val);
		}
		fprintf(stderr, " -%c --%-11s%-16s%s\n", option.val, option.name, parameter.c_str(), description.c_str());
	}
	
	exit(1);
}

void Jabberite::parse_options(int argc, char** argv)
{
	port = -1;
	
	std::string short_options = "ha:p:s:P:r:";
	const struct option basic_long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "account", 1, NULL, 'a' },
		{ "password", 1, NULL, 'p' },
		{ "server", 1, NULL, 's' },
		{ "room", 1, NULL, 'r' },
		{ "port", 1, NULL, 'P' },
		{ "nickname", 1, NULL, 'n' },
	};
	std::vector<option> long_options(basic_long_options, basic_long_options + (sizeof(basic_long_options) / sizeof(*basic_long_options)));
	
	std::vector<option> extra_options = this->extra_options();
	for (const option& option : extra_options) {
		long_options.push_back(option);
		short_options += option.val;
		if (option.has_arg) {
			short_options += ':';
		}
	}
	long_options.insert(long_options.end(), extra_options.begin(), extra_options.end());
	
	option empty = { NULL, 0, NULL, 0 };
	long_options.push_back(empty);
	
	
	int next_option;
	do {
		next_option = getopt_long (argc, argv, short_options.c_str(), &long_options[0], NULL);
		switch (next_option)
		{
		case 'h':
			/* -h or --help */
			print_usage(argv[0], extra_options);
			break;
		case 'a':
			/* -a or --account */
			username = std::string(optarg);
			break;
		case 'p':
			/* -o or --password */
			password = std::string(optarg);
			break;
		case 's':
			/* -s or --server */
			server = std::string(optarg);
			break;
		case 'r':
			/* -r or --room */
			room_name = std::string(optarg);
			break;
		case 'P':
			/* -P or --port */
			try {
				port = std::stoi(std::string(optarg));
			} catch(std::invalid_argument) {
				print_usage(argv[0], extra_options);
			}
			break;
		case 'n':
			/* -n or --nickname */
			nickname = std::string(optarg);
			break;
		case '?':
			/* Invalid option */
			print_usage(argv[0], extra_options);
			break;
		case -1:
			/* Done with options */
			break;
		default:
			if (!process_option(next_option, optarg)) {
				/* Something else: unexpected.*/
				abort ();
			}
		}
	} while (next_option != -1);
	
	if (username.empty()) {
		char username_buffer[128];
		printf("XMPP account: ");
		if (!fgets(username_buffer, sizeof(username_buffer), stdin)) {
			fprintf(stderr, "Failed to read username.\n");
			abort();
		}
		if (strchr(username_buffer, '\n')) {
			*strchr(username_buffer, '\n') = 0;
		}
		username = std::string(username_buffer);
	}
	
	if (password.empty()) {
		char* password_buffer = getpass("Password: ");
		password = std::string(password_buffer);
	}
	
	if (server.empty()) {
		char server_buffer[128];
		printf("Conference server: ");
		if (!fgets(server_buffer, sizeof(server_buffer), stdin)) {
			fprintf(stderr, "Failed to read conference server.\n");
			abort();
		}
		if (strchr(server_buffer, '\n')) {
			*strchr(server_buffer, '\n') = 0;
		}
		server = std::string(server_buffer);
	}
	
	if (room_name.empty()) {
		char room_buffer[128];
		printf("Room name: ");
		if (!fgets(room_buffer, sizeof(room_buffer), stdin)) {
			fprintf(stderr, "Failed to read room name.\n");
			abort();
		}
		if (strchr(room_buffer, '\n')) {
			*strchr(room_buffer, '\n') = 0;
		}
		room_name = std::string(room_buffer);
	}
	
	if (nickname.empty()) {
		size_t at_pos = username.find('@');
		if (at_pos == std::string::npos) {
			nickname = username;
		} else {
			nickname = username.substr(0, at_pos);
		}
	}
}
