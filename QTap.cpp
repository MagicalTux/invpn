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

struct tap_packet {
	struct tun_pi packet_info;
	union _data {
		struct ether_header eth_hdr;
		char raw[TAP_MAX_MTU];
	} data;
} __attribute__((packed));

QTap::QTap(const QString &pref_name, QObject *parent): QObject(parent) {
	struct ifreq ifr;

	tap_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

	if (tap_fd < 0) {
		qDebug("failed to open tun port, make sure module is loaded and you can access it");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP;

	if (!pref_name.isEmpty()) {
		strncpy(ifr.ifr_name, pref_name.toLatin1().constData(), IFNAMSIZ);
	}

	if (ioctl(tap_fd, TUNSETIFF, (void *) &ifr) < 0) {
		qDebug("tap: unable to set tunnel. Make sure you have the appropriate privileges");
		close(tap_fd);
		tap_fd = -1;
		return;
	}

	name = QString::fromLatin1(ifr.ifr_name);
	notifier = new QSocketNotifier(tap_fd, QSocketNotifier::Read, this);
	connect(notifier, SIGNAL(activated(int)), this, SLOT(activity(int)));
}

bool QTap::isValid() const {
	return tap_fd > 0;
}

const QString &QTap::getName() const {
	return name;
}

void QTap::activity(int fd) {
	if (fd != tap_fd) return;
	struct tap_packet buffer;
	int len = read(tap_fd, &buffer, sizeof(buffer));

	// we actually don't care about the tun_pi part, strip down to what's below ethernet (only keep proto)
	QByteArray data(buffer.data.raw+12, len-4-12);
	QByteArray src_hw(buffer.data.raw+6, 6);
	QByteArray dst_hw(buffer.data.raw, 6);

	packet(src_hw, dst_hw, data);
}

void QTap::setMac(const QByteArray &mac) {
	if (tap_fd <= 0) return;

	int s;
	struct ifreq ifhw;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&ifhw, 0, sizeof(ifhw));
	strncpy(ifhw.ifr_name, name.toLatin1().constData(), IFNAMSIZ);
	ifhw.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(&ifhw.ifr_hwaddr.sa_data, mac.constData(), ETH_ALEN);
	if (ioctl(s, SIOCSIFHWADDR, (void*) &ifhw) < 0) {
		qDebug("SIOCSIFHWADDR failed");
		close(s);
		return;
	}
	close(s);
}

void QTap::write(const QByteArray &dat) {
	if (tap_fd <= 0) return;
	QByteArray cp(4, '\x00');
	cp.append(dat);
	int res = ::write(tap_fd, cp.constData(), cp.size());
	if (res != cp.size()) {
		qDebug("QTap::write: failed to write");
	}
}

