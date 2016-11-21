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
	jabberite->conversation = conversation;
	
	jabberite->room->search_channels();
	jabberite->connected();
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



class JabberiteChannelInterface final : public np1sec::ChannelInterface
{
	public:
	JabberiteChannelInterface(Jabberite* jabberite_, np1sec::Channel* channel_): jabberite(jabberite_), channel(channel_) {}
	void user_joined(const std::string& username);
	void user_left(const std::string& username);
	void user_authenticated(const std::string& username, const np1sec::PublicKey& public_key);
	void user_authentication_failed(const std::string& username);
	void user_authorized_by(const std::string& user, const std::string& target);
	void user_promoted(const std::string& username);
	
	void joined();
	void authorized();
	
	void joined_chat();
	void user_joined_chat(const std::string& username);
	void message_received(const std::string& username, const std::string& message);
	
	protected:
	int id() { return jabberite->channel_id(channel); }
	
	public:
	Jabberite* jabberite;
	np1sec::Channel* channel;
};

void JabberiteChannelInterface::user_joined(const std::string& username)
{
	jabberite->user_joined(id(), username);
}

void JabberiteChannelInterface::user_left(const std::string& username)
{
	jabberite->user_left(id(), username);
}

void JabberiteChannelInterface::user_authenticated(const std::string& username, const np1sec::PublicKey& public_key)
{
	jabberite->user_authenticated(id(), username, public_key);
}

void JabberiteChannelInterface::user_authentication_failed(const std::string& username)
{
	jabberite->user_authentication_failed(id(), username);
}

void JabberiteChannelInterface::user_authorized_by(const std::string& user, const std::string& target)
{
	jabberite->user_authorized_by(id(), user, target);
}

void JabberiteChannelInterface::user_promoted(const std::string& username)
{
	jabberite->user_promoted(id(), username);
}

void JabberiteChannelInterface::joined()
{
	jabberite->joined(id());
}

void JabberiteChannelInterface::authorized()
{
	jabberite->authorized(id());
}

void JabberiteChannelInterface::joined_chat()
{
	jabberite->joined_chat(id());
}

void JabberiteChannelInterface::user_joined_chat(const std::string& username)
{
	jabberite->user_joined_chat(id(), username);
}

void JabberiteChannelInterface::message_received(const std::string& username, const std::string& message)
{
	jabberite->message_received(id(), username, message);
}



class JabberiteRoomInterface : public np1sec::RoomInterface
{
	public:
	JabberiteRoomInterface(Jabberite* jabberite): m_jabberite(jabberite) {}
	void send_message(const std::string& message);
	np1sec::TimerToken* set_timer(uint32_t interval, np1sec::TimerCallback* callback);
	
	np1sec::ChannelInterface* new_channel(np1sec::Channel* channel);
	void channel_removed(np1sec::Channel* channel);
	void joined_channel(np1sec::Channel* channel);
	void disconnected();
	
	protected:
	Jabberite* m_jabberite;
};

void JabberiteRoomInterface::send_message(const std::string& message)
{
	if (!m_jabberite->frozen) {
		purple_conv_chat_send(PURPLE_CONV_CHAT(m_jabberite->conversation), message.c_str());
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

np1sec::ChannelInterface* JabberiteRoomInterface::new_channel(np1sec::Channel* channel)
{
	JabberiteChannelInterface* interface = new JabberiteChannelInterface(m_jabberite, channel);
	int id = m_jabberite->add_channel(interface);
	m_jabberite->new_channel(id, channel);
	return interface;
}

void JabberiteRoomInterface::channel_removed(np1sec::Channel* channel)
{
	int id = m_jabberite->remove_channel(channel);
	m_jabberite->channel_removed(id);
}

void JabberiteRoomInterface::joined_channel(np1sec::Channel* channel)
{
	int id = m_jabberite->channel_id(channel);
	m_jabberite->joined_channel(id);
}

void JabberiteRoomInterface::disconnected()
{
	m_jabberite->disconnected();
}



Jabberite::Jabberite():
	account(nullptr),
	connection(nullptr),
	conversation(nullptr),
	frozen(false),
	room(nullptr)
{
}

void Jabberite::create_channel()
{
	if (room) {
		room->create_channel();
	}
}

void Jabberite::join_channel(int id)
{
	if (room) {
		np1sec::Channel* channel = this->channel(id);
		if (channel) {
			room->join_channel(channel);
		}
	}
}

void Jabberite::authorize(std::string username)
{
	if (room) {
		room->authorize(username);
	}
}

void Jabberite::votekick(std::string username, bool kick)
{
	if (room) {
		room->votekick(username, kick);
	}
}

void Jabberite::send_chat(std::string message)
{
	if (room) {
		room->send_chat(message);
	}
}

np1sec::Channel* Jabberite::channel(int id)
{
	if (id < 0 || (size_t) id >= channels.size()) {
		return nullptr;
	}
	if (!channels[id]) {
		return nullptr;
	}
	return channels[id]->channel;
}

int Jabberite::channel_id(np1sec::Channel* channel)
{
	for (int i = 0; (size_t)i < channels.size(); i++) {
		if (channels[i] && channels[i]->channel == channel) {
			return i;
		}
	}
	return -1;
}

int Jabberite::add_channel(JabberiteChannelInterface* interface)
{
	int id = channels.size();
	channels.push_back(interface);
	return id;
}

int Jabberite::remove_channel(np1sec::Channel* channel)
{
	int id = channel_id(channel);
	if (id != -1) {
		if (channels[id]) {
			delete channels[id];
			channels[id] = nullptr;
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
	room = new np1sec::Room(interface, nickname, np1sec::PrivateKey::generate());
	
	
	
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
