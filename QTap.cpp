#include "QTap.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

QTap::QTap() {
	struct ifreq ifr;

	tap_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

	if (tap_fd < 0) {
		qDebug("failed to open tun port, make sure module is loaded and you can access it");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP;

	if (ioctl(tap_fd, TUNSETIFF, (void *) &ifr) < 0) {
		qDebug("tap: unable to set tunnel. Make sure you have the appropriate privileges");
		close(tap_fd);
		tap_fd = -1;
		return;
	}

	name = QString::fromLatin1(ifr.ifr_name);
}

