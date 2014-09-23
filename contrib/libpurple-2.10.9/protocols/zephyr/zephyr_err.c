#include "zephyr_err.h"

#ifdef __STDC__
#define NOARGS void
#else
#define NOARGS
#define const
#endif

static const char * const text[] = {
	"Packet too long or buffer too small",
	"Notice header too large",
	"Illegal value in notice",
	"Can't get host manager port",
	"Can't assign port",
	"Bad packet format",
	"Incompatible version numbers",
	"No port opened",
	"No notices match criteria",
	"Input queue too long",
	"Hostmanager not responding",
	"Internal error",
	"No previous call to ZLocateUser",
	"No more locations available",
	"Field too long for buffer",
	"Improperly formatted field",
	"SERVNAK received",
	"Server could not verify authentication",
	"Not logged-in",
	"No previous call to ZRetrieveSubscriptions",
	"No more subscriptions available",
	"Too many subscriptions to transmit",
	"End of file detected during read",
    0
};

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};
struct et_list {
    struct et_list *next;
    const struct error_table * table;
};
extern struct et_list *_et_list;

static const struct error_table et = { text, -772103680L, 23 };

static struct et_list link = { 0, 0 };

void initialize_zeph_error_table (NOARGS) {
    if (!link.table) {
        link.next = _et_list;
        link.table = &et;
        _et_list = &link;
    }
}
