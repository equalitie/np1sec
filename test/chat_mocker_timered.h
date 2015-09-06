/**
   This is a mock/simulator of a multi party chat protocol runing on the
   same machine for the purpose of testing np1sec

   Authors: Vmon, 2015-01: initial version
 */
extern "C" {
#include <assert.h>
}

#include <map>
#include <list>
#include <queue>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <event2/event.h>

#include "src/logger.h"
#include "test/chat_mocker.h"
using namespace std;
using namespace np1sec;

#ifndef TEST_CHAT_MOCKER_TIMERED_H_
#define TEST_CHAT_MOCKER_TIMERED_H_
extern Logger mock_logger;

/**
   This class store the information about different participants
   including their receive and send functions
 */

void chat_mocker_np1sec_plugin_receive_handler(std::string room_name, std::string np1sec_message, void* aux_data);

void intermediate_cb(evutil_socket_t fd, short what, void* arg);

// A simple timeout event manager
class EventManager
{
  private:
    std::map<std::string, struct event*> timers;
    struct event_base* base;

    std::string next_identifier();

    unsigned long long uid = 0;

  public:
    EventManager();
    EventManager(struct event_base* base);
    std::string* add_timeout(event_callback_fn cb, void* arg, const timeval* timeout);
    struct event* get(std::string* identifier);
    int size();
    void dispatch_event_loop();
    void end_event_loop();
    void remove_timeout(std::string* identifier);
};

/**
   This client simulate both client and server.
   as everythnig happens locally
 */
class ChatMockerTimered : public ChatMocker
{
  protected:
    const timeval c_check_receive_interval = {0, 10 * 1000};

    EventManager event_manager;

    /**
     * Initialize the event manager with a libevent event_base
     */
    void initialize_event_manager(struct event_base* base) { event_manager = EventManager(base); }

  public:
    /**
     * End libevent's loop
     */
    void end_event_loop() { event_manager.end_event_loop(); }

    /**
     * Add a new timeout event to the event manager
     */
    virtual std::string* add_timeout(void* arg, const uint32_t interval)
    {
        struct timeval timeout;
        timeout.tv_sec = interval / 1000;
        timeout.tv_usec = (long)(interval % 1000) * 1000;

        return event_manager.add_timeout(intermediate_cb, arg, &timeout);
    }

    /**
     * Remove a timeout event from the event manager
     */
    virtual void remove_timeout(std::string* identifier) { event_manager.remove_timeout(identifier); }

    friend void check_receive_queue(evutil_socket_t fd, short what, void* arg);

    void dispatch_event_loop();
};

#endif // TEST_CHAT_MOCKER_H_
