#include <QObject>
#include <QSqlDatabase>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslSocket>
#include <QTimer>
#include <QPointer>
#include "QTap.hpp"
#include "InVpnSslServer.hpp"

class InVpnNode;

struct invpn_route_info {
	qint64 stamp;
	QPointer<InVpnNode> peer;
};

class InVpn: public QObject {
	Q_OBJECT;
public:
	InVpn();

public slots:
	void packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data);
	bool isValid();
	void accept(QSslSocket*);

	void sslErrors(const QList<QSslError>&);
	void socketReady();
	void socketLost();
	void socketError(QAbstractSocket::SocketError);

	void announce();
	void tryConnect();
	void announcedRoute(const QByteArray &mac, InVpnNode *peer, qint64 stamp, const QByteArray &pkt);

	void route(const QByteArray&); // route a 0x80 packet to appropriate node

signals:
	void broadcast(const QByteArray&);

private:
	QTap *tap;
	InVpnSslServer *server;

	qint64 broadcastId();
	qint64 bc_last_id;

	QMap<QByteArray, InVpnNode*> nodes;
	QMap<QByteArray, struct invpn_route_info> routes;

	QSqlDatabase db;

	QSslKey ssl_key;
	QSslCertificate ssl_cert;
	QList<QSslCertificate> ssl_ca;

	QByteArray mac;

	QTimer announce_timer;
	QTimer connect_timer;

	// settings
	void parseCmdLine();
	QString key_path;
	QString cert_path;
	QString ca_path;
	QString db_path;
	QString init_seed; // initial peer if none found
	int port;
};

// helper
static inline QString invpn_socket_name(const QAbstractSocket *s) {
	QHostAddress h = s->peerAddress();
	if (h.protocol() == QAbstractSocket::IPv4Protocol) {
		return h.toString()+QString(":")+QString::number(s->peerPort());
	}
	return QString("[")+h.toString()+QString("]:")+QString::number(s->peerPort());
}

