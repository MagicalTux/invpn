#include "InVpn.hpp"
#include "InVpnNode.hpp"
#include <QCoreApplication>
#include <QStringList>
#include <QFile>
#include <QSslConfiguration>
#include <QDateTime>
#include <qendian.h>
#include <unistd.h>
#include <fcntl.h>

InVpn::InVpn() {
	tap = NULL;
	tap_fd_restore = -1;
	settings = NULL;
	cache = NULL;
	bc_last_id = 0;

	parseCmdLine();

	// initialize SSL
	QFile key_file(conf_key_path);
	if (!key_file.open(QIODevice::ReadOnly)) {
		qDebug("Could not open key file");
		QCoreApplication::exit(1);
		return;
	}
	ssl_key = QSslKey(&key_file, QSsl::Rsa);
	if (ssl_key.isNull()) {
		qDebug("failed to parse key file");
		QCoreApplication::exit(1);
		return;
	}
	key_file.close();
	ssl_cert = QSslCertificate::fromPath(conf_cert_path, QSsl::Pem, QRegExp::FixedString).at(0);
	ssl_ca = QSslCertificate::fromPath(conf_ca_path, QSsl::Pem);

	if (ssl_cert.isNull()) {
		qDebug("failed to parse cert");
		QCoreApplication::exit(1);
		return;
	}
	if (ssl_ca.size() == 0) {
		qDebug("failed to parse CA file");
		QCoreApplication::exit(1);
		return;
	}

	// Set CA list for all future configs
	QSslConfiguration config = QSslConfiguration::defaultConfiguration();
	config.setCaCertificates(ssl_ca);
	config.setLocalCertificate(ssl_cert);
	config.setPrivateKey(ssl_key);
	config.setPeerVerifyMode(QSslSocket::VerifyPeer);
	QSslConfiguration::setDefaultConfiguration(config);

	QString tmpmac = ssl_cert.subjectInfo(QSslCertificate::CommonName);
	mac = QByteArray::fromHex(tmpmac.toLatin1().replace(":",""));

	server = new InVpnSslServer();
	if (!server->listen(QHostAddress::Any, conf_port)) {
		qDebug("failed to listen to net");
		QCoreApplication::exit(1);
		return;
	}

	tap = new QTap("invpn%d", mac, this, tap_fd_restore);
	if (!tap->isValid()) {
		delete tap;
		tap = NULL;
		return;
	}

	connect(server, SIGNAL(ready(QSslSocket*)), this, SLOT(accept(QSslSocket*)));
	connect(tap, SIGNAL(packet(const QByteArray&, const QByteArray&, const QByteArray&)), this, SLOT(packet(const QByteArray&, const QByteArray&, const QByteArray&)));
	connect(&announce_timer, SIGNAL(timeout()), this, SLOT(announce()));
	connect(&connect_timer, SIGNAL(timeout()), this, SLOT(tryConnect()));

	announce_timer.setInterval(5000);
	announce_timer.setSingleShot(false);
	announce_timer.start();
	connect_timer.setInterval(60000);
	connect_timer.setSingleShot(false);
	connect_timer.start();

	qDebug("got interface: %s", qPrintable(tap->getName()));

	tryConnect(); // try to connect to stuff now
}

void InVpn::tryConnect() {
	// we want at least two links established, let's count now!
	int count = 0;

	auto i = nodes.begin();
	while(i != nodes.end()) {
		if (i.value()->isLinked()) count++;
		i++;
	}
	if (count >= 2) return;

	QStringList keys = cache->allKeys();
	while((keys.size() > 0) && (count < 2)) {
		// take a random key
		QString k = keys.takeAt(qrand() % keys.size());
		// check if already connected
		QByteArray m = QByteArray::fromHex(k.toLatin1().replace(":",""));
		if ((nodes.contains(m)) && (nodes.value(m)->isLinked())) continue;

		QVariantList v = cache->value(k).toList();
		connectTo(k, QHostAddress(v.at(0).toString()), v.at(1).toInt());
	}

	// format is either: 127.0.0.1:1234 [::1]:1234
	// Because of the way this works, placing an IPv6 without brackets works too: ::1:1234
	// IPv4 with brackets works too: [127.0.0.1]:1234
	if (conf_init_seed.isNull()) {
//		qDebug("no node to connect to, giving up");
		return;
	}

	
	int pos = conf_init_seed.indexOf('@');
	if (pos == -1) {
		qDebug("Bad syntax for initial seed, giving up");
		return;
	}
	QString rmac = conf_init_seed.mid(0, pos);
	QString addr = conf_init_seed.mid(pos+1);

	pos = addr.lastIndexOf(':');
	if (pos == -1) {
		qDebug("port missing, giving up");
		return;
	}

	int port = addr.mid(pos+1).toInt();
	QString tip = addr.mid(0, pos);

	if ((tip[0] == '[') && (tip.at(tip.size()-1) == ']')) {
		tip = tip.mid(1, tip.size()-2);
	}
	QHostAddress ip(tip);
	if (ip.isNull()) {
		qDebug("malformed initial seed ip, giving up");
		return;
	}

	connectTo(rmac, ip, port);
}

void InVpn::connectTo(const QString &id, const QHostAddress &ip, quint16 port) {
	qDebug("trying to connect to %s on port %d", qPrintable(ip.toString()), port);

	QSslSocket *s = new QSslSocket(this);
	connect(s, SIGNAL(connected()), s, SLOT(startClientEncryption()));
	connect(s, SIGNAL(sslErrors(const QList<QSslError>&)), this, SLOT(sslErrors(const QList<QSslError>&)));
	connect(s, SIGNAL(encrypted()), this, SLOT(socketReady()));
	connect(s, SIGNAL(disconnected()), this, SLOT(socketLost()));
	connect(s, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(socketError(QAbstractSocket::SocketError)));
	s->connectToHost(ip, port);
	s->setPeerVerifyName(id);
}

void InVpn::announce() {
	// broadcast to all peers that we are here
	QByteArray pkt;

	qint64 ts = qToBigEndian(broadcastId());

	pkt.append((char)1); // version
	pkt.append((char*)&ts, 8);
	pkt.append(mac);
	quint16 p = conf_port;
	p = qToBigEndian(p);
	pkt.append((char*)&p, 2);

	if (conf_no_incoming) {
		// we don't accept incoming connections (firewall, temporary node, etc), so don't broadcast an ip
		pkt.append((char)0);
		pkt.prepend((char)1); // version + include ip (type 0 = no ip)
	} else {
		pkt.prepend((char)0); // version + ask receipient to detect our ip
	}

	quint16 len = pkt.size();
	len = qToBigEndian(len);
	pkt.prepend((char*)&len, 2);

	broadcast(pkt);
}

qint64 InVpn::broadcastId() {
	// return a milliseconds unique timestamp, let's hope we won't have a sustained 1000 pkt/sec of broadcast
	qint64 now = QDateTime::currentMSecsSinceEpoch();
	if (now <= bc_last_id) {
		bc_last_id++;
		return bc_last_id;
	}
	bc_last_id = now;
	return now;
}

void InVpn::accept(QSslSocket*s) {
	connect(s, SIGNAL(sslErrors(const QList<QSslError>&)), this, SLOT(sslErrors(const QList<QSslError>&)));
	connect(s, SIGNAL(disconnected()), this, SLOT(socketLost()));
	connect(s, SIGNAL(encrypted()), this, SLOT(socketReady()));
	connect(s, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(socketError(QAbstractSocket::SocketError)));
	s->startServerEncryption();
}

void InVpn::sslErrors(const QList<QSslError>&l) {
	qDebug("SSL errors in peer connection:");
	for(int i = 0; i < l.size(); i++) {
		qDebug(" * %s", qPrintable(l.at(i).errorString()));
	}
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if (!s) {
		qDebug("Source was not a QsslSocket? :(");
		return;
	}
	s->deleteLater();
}

void InVpn::socketReady() {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if (!s) return;

	QSslCertificate p = s->peerCertificate();
	QString tmpmac = p.subjectInfo(QSslCertificate::CommonName); // xx:xx:xx:xx:xx:xx
	QByteArray m = QByteArray::fromHex(tmpmac.toLatin1().replace(":",""));

	if (m == mac) {
		// connected to myself?!
		qDebug("connected to self, closing");
		s->disconnect();
		s->deleteLater();
	}

	// do we know this node ?
	if (!nodes.contains(m)) {
		nodes.insert(m, new InVpnNode(this, m));
		connect(this, SIGNAL(broadcast(const QByteArray&)), nodes.value(m), SLOT(push(const QByteArray&)));
	}
	if (!nodes.value(m)->setLink(s)) {
		// already got a link to that node?
		qDebug("already got a link to this guy, closing it");
		s->disconnect();
		s->deleteLater();
	}

	announce(); // send announces now to update our routes
}

void InVpn::socketLost() {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if (!s) return;

//	QString peer = invpn_socket_name(s);
//	qDebug("lost peer %s", qPrintable(peer));
//
//	peers.remove(peer);
	s->deleteLater();
}

void InVpn::socketError(QAbstractSocket::SocketError) {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if (!s) return;

	qDebug("error from socket: %s", qPrintable(s->errorString()));
	s->deleteLater();
}

bool InVpn::isValid() {
	if (tap == NULL) return false;
	return true;
}

void InVpn::packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data) {
	if (src_hw != mac) {
		qDebug("dropped packet from wrong mac addr");
		return;
	}
//	qDebug("packet data: [%s] => [%s] %s", src_hw.toHex().constData(), dst_hw.toHex().constData(), data.toHex().constData());

	if (dst_hw == QByteArray(6, '\xff')) {
		// broadcast!
		QByteArray pkt;

		qint64 ts = qToBigEndian(broadcastId());

		pkt.append((char*)&ts, 8);
		pkt.append(src_hw);
		pkt.append(data);

		pkt.prepend((char)0x81); // broadcast
		quint16 len = pkt.size();
		len = qToBigEndian(len);
		pkt.prepend((char*)&len, 2);

//		qDebug("broadcast: %s", pkt.toHex().constData());
		broadcast(pkt);
		return;
	}
	if (!routes.contains(dst_hw)) {
//		qDebug("Packet to unroutable mac addr %s ignored", dst_hw.toHex().constData());
		return;
	}

	QByteArray pkt;
	pkt.append(dst_hw);
	pkt.append(src_hw);
	pkt.append(data);

	pkt.prepend((char)0x80); // targetted
	quint16 len = pkt.size();
	len = qToBigEndian(len);
	pkt.prepend((char*)&len, 2);

	route(pkt);
//	nodes.value(dst_hw).push(pkt);
}

void InVpn::announcedRoute(const QByteArray &dmac, InVpnNode *peer, qint64 stamp, const QHostAddress &addr, quint16 port, const QByteArray &pkt) {
//	qDebug("got route to %s stamp %lld, connectable via %s port %d", dmac.toHex().constData(), stamp, qPrintable(addr.toString()), port);
	if (dmac == mac) return; // to myself
	if (!nodes.contains(dmac)) {
		nodes.insert(dmac, new InVpnNode(this, dmac));
		connect(this, SIGNAL(broadcast(const QByteArray&)), nodes.value(dmac), SLOT(push(const QByteArray&)));
	}
	if (routes.contains(dmac)) {
		if (routes.value(dmac).stamp >= stamp) return;
		routes[dmac].stamp = stamp;
		routes[dmac].peer = peer;
		broadcast(pkt);
		return;
	}
	struct invpn_route_info s;
	s.peer = peer;
	s.stamp = stamp;
	routes.insert(dmac, s);
	broadcast(pkt);

	// also insert into db
	if (!addr.isNull()) {
		QString final_mac = dmac.toHex();
		final_mac = final_mac.insert(10,':').insert(8,':').insert(6,':').insert(4,':').insert(2,':');
		cache->setValue(final_mac, QVariantList() << addr.toString() << port);
	}
}

void InVpn::routeBroadcast(const QByteArray &pkt) {
	if ((unsigned char)pkt.at(2) != 0x81) return; // not a broadcast packet
	QByteArray src_mac = pkt.mid(11, 6);
	if (src_mac == mac) return;

	if (!nodes.contains(src_mac)) return;

	qint64 stamp = qFromBigEndian(*(qint64*)pkt.mid(3, 8).constData());

	if (!nodes.value(src_mac)->checkStamp(stamp)) return;

	QByteArray tap_pkt(6, '\xff');
	tap_pkt.append(pkt.mid(11));

	tap->write(tap_pkt);
	broadcast(pkt);
}

void InVpn::route(const QByteArray &pkt) {
	if ((unsigned char)pkt.at(2) != 0x80) return; // not a directed packet
	QByteArray dst_mac = pkt.mid(3, 6);
	if (dst_mac == mac) {
		// that's actually a packet for us
		tap->write(pkt.mid(3));
		return;
	}

//	qDebug("route pkt to %s", dst_mac.toHex().constData());
	if (!routes.contains(dst_mac)) return;
	if (!routes.value(dst_mac).peer) return;
	routes.value(dst_mac).peer->push(pkt);
}

void InVpn::parseCmdLine() {
	// set default settings, then try to parse cmdline
	config_file = "conf/invpn.conf";
	conf_cache_file = "conf/invpn.cache";
	conf_port = 41744;
	conf_key_path = "conf/client.key";
	conf_cert_path = "conf/client.crt";
	conf_ca_path = "conf/ca.crt";
	conf_no_incoming = false;

	QStringList cmdline = QCoreApplication::arguments();

	// Why isn't there a cmdline parser included with Qt? ;_;
	for(int i = 1; i < cmdline.size(); i++) {
		QString tmp = cmdline.at(i);
		if ((tmp == "-c") && (cmdline.size() > i+1)) {
			config_file = cmdline.at(i+1); i++; continue;
		}
		if ((tmp == "--tunfd") && (cmdline.size() > i+1)) {
			tap_fd_restore = cmdline.at(i+1).toInt(); i++; continue;
		}
		// ignore unrecognized args
	}

	settings = new QSettings(config_file, QSettings::IniFormat, this);
	cache = new QSettings(conf_cache_file, QSettings::IniFormat, this);

	reloadSettings();
}

void InVpn::reloadSettings() {
	settings->beginGroup("ssl");
	conf_key_path = settings->value("key", conf_key_path).toString();
	conf_cert_path = settings->value("cert", conf_cert_path).toString();
	conf_ca_path = settings->value("ca", conf_ca_path).toString();
	settings->endGroup();
	settings->beginGroup("network");
	conf_port = settings->value("port", conf_port).toInt();
	conf_no_incoming = settings->value("no_incoming", conf_no_incoming).toInt();
	conf_init_seed = settings->value("init").toString();
	QString new_cache_file = settings->value("cache", conf_cache_file).toString();
	settings->endGroup();
	if (new_cache_file != conf_cache_file) {
		cache->sync();
		delete cache;
		conf_cache_file = new_cache_file;
		cache = new QSettings(conf_cache_file, QSettings::IniFormat, this);
	}
}

void InVpn::quit() {
	qDebug("clean quit");
	QCoreApplication::quit();
}

void InVpn::restart() {
	qDebug("restart invpn!");
	int fd = tap->getFd();
	qDebug("TAP @ %d", fd);
	fcntl(fd, F_SETFD, 0); // ensure FD_CLOEXEC is not set
	char* const targv[] = { strdup(QCoreApplication::applicationFilePath().toLatin1().constData()), strdup("-c"), strdup(config_file.toLatin1().constData()), strdup("--tunfd"), strdup(QByteArray::number(fd).constData()), NULL };
	execve(targv[0], targv, environ);
	perror("execve");
	qDebug("exec failed");
}

