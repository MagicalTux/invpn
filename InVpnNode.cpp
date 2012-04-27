#include "InVpnNode.hpp"
#include "InVpn.hpp"
#include <qendian.h>

InVpnNode::InVpnNode(InVpn *_parent, const QByteArray &_mac): QObject(_parent) {
	parent = _parent;
	mac = _mac;
	link = NULL;
	last_bcast = 0;
}

bool InVpnNode::setLink(QSslSocket *_link) {
	if (link != NULL) return false;
	link = _link;
	readbuf.clear();
	connect(link, SIGNAL(disconnected()), this, SLOT(socketLost()));
	connect(link, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(socketError(QAbstractSocket::SocketError)));
	connect(link, SIGNAL(readyRead()), this, SLOT(socketRead()));
	return true;
}

bool InVpnNode::checkStamp(qint64 id) {
	if (id <= last_bcast) return false;
	last_bcast = id;
	return true;
}

void InVpnNode::socketRead() {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if ((s!=link) || (link == NULL)) return;

	readbuf += link->readAll();

	while(true) {
		if (readbuf.size() < 2) break;
		quint16 len = *(quint16*)readbuf.constData();
		len = qFromBigEndian(len);
		if (readbuf.size() < len+2) break;

		QByteArray pkt = readbuf.left(len+2);
		readbuf.remove(0, len+2);
		handlePacket(pkt);
	}
}

void InVpnNode::handlePacket(const QByteArray&pkt) {
	int type = (unsigned char)pkt.at(2);

	switch(type) {
		case 0x00:
			// details on a directly connected node. Generate packet 0x01 from this
			{
				QByteArray new_pkt;
				new_pkt.append((char)0x01);
				new_pkt.append(pkt.mid(3));// version + id + mac + port
				QHostAddress h = link->peerAddress();
				switch(h.protocol()) {
					case QAbstractSocket::IPv4Protocol:
						{
							new_pkt.append((char)0x01);
							quint32 ip = qToBigEndian(h.toIPv4Address());
							new_pkt.append((char*)&ip, 4);
						}
						break;
					case QAbstractSocket::IPv6Protocol:
						{
							new_pkt.append((char)0x02);
							Q_IPV6ADDR ip = h.toIPv6Address();
							new_pkt.append((char*)&ip, 16);
						}
						break;
					default:
						new_pkt.append((char)0x00);
						break;
				}
				// prepend length
				quint16 len = new_pkt.size();
				len = qToBigEndian(len);
				new_pkt.prepend((char*)&len, 2);

				qint64 stamp = qFromBigEndian(*(qint64*)pkt.mid(4, 8).constData());
				quint16 port = qFromBigEndian(*(quint16*)(pkt.constData()+18));

				parent->announcedRoute(pkt.mid(12, 6), this, stamp, h, port, new_pkt);
			}
			break;
		case 0x01:
			// details on a remote node
			{
				qint64 stamp = qFromBigEndian(*(qint64*)pkt.mid(4, 8).constData());
				QHostAddress h;
				quint16 port = qFromBigEndian(*(quint16*)(pkt.constData()+18));
				int type = pkt.at(20);
				switch(type) {
					case 1:
						{
							quint32 ip = qFromBigEndian(*(quint32*)(pkt.constData()+21));
							h.setAddress(ip);
						}
						break;
					case 2:
						{
							Q_IPV6ADDR ip = *(Q_IPV6ADDR*)(pkt.constData()+21);
							h.setAddress(ip);
						}
						break;
				}
				parent->announcedRoute(pkt.mid(12, 6), this, stamp, h, port, pkt);
			}
			break;
		case 0x80:
			// targetted packet
			parent->route(pkt);
			break;
		case 0x81:
			// broadcast - let the sender manage it
			parent->routeBroadcast(pkt);
			break;
	}
}

void InVpnNode::socketLost() {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if ((s!=link) || (link == NULL)) return;

	link->deleteLater();
	link = NULL;
}

void InVpnNode::socketError(QAbstractSocket::SocketError) {
	QSslSocket *s = qobject_cast<QSslSocket*>(sender());
	if ((s!=link) || (link == NULL)) return;

	link->deleteLater();
	link = NULL;
}

bool InVpnNode::isLinked() const {
	return (link != NULL);
}

void InVpnNode::push(const QByteArray&msg) {
	if (link == NULL) return;
	link->write(msg);
}

