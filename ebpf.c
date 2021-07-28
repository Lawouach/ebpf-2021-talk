#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6

int http_filter(struct __sk_buff *skb) {
	u8 *cursor = 0;

    // let's not care for anything not Ethernet or TCP
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)) {
		return 0;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	if (ip->nextp != IP_TCP) {
		return 0;
	}

    return -1;
}
