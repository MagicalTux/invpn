#include <QObject>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslSocket>
#include <QTimer>
#include <QPointer>
#include <QSettings>
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

	void connectTo(const QString &id, const QHostAddress &addr, quint16 port);

public slots:
	void reloadSettings();

	void quit();
	void restart();

	void packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data);
	bool isValid();
	void accept(QSslSocket*);

	void sslErrors(const QList<QSslError>&);
	void socketReady();
	void socketLost();
	void socketError(QAbstractSocket::SocketError);

	void announce();
	void tryConnect();
	void announcedRoute(const QByteArray &mac, InVpnNode *peer, qint64 stamp, const QHostAddress&, quint16 port, const QByteArray &pkt);
	void cleanupRoutes();

	void route(const QByteArray&); // route a 0x80 packet to appropriate node
	void routeBroadcast(const QByteArray&); // route a 0x8& packet to appropriate nodes

signals:
	void broadcast(const QByteArray&);

private:
	QTap *tap;
	InVpnSslServer *server;

	qint64 broadcastId();
	qint64 bc_last_id;

	QMap<QByteArray, InVpnNode*> nodes;
	QMap<QByteArray, struct invpn_route_info> routes;

	QSslKey ssl_key;
	QSslCertificate ssl_cert;
	QList<QSslCertificate> ssl_ca;

	QByteArray mac;

	QTimer announce_timer;
	QTimer connect_timer;
	QTimer route_timer;

	// settings
	QString config_file;
	void parseCmdLine();
	QString conf_cache_file;
	QString conf_key_path;
	QString conf_cert_path;
	QString conf_ca_path;
	QString conf_db_path;
	QString conf_init_seed; // initial peer if none found
	int conf_port;
	int tap_fd_restore;
	bool conf_no_incoming;
	bool conf_no_relay;

	QSettings *settings;
	QSettings *cache;
};

// helper
static inline QString invpn_socket_name(const QAbstractSocket *s) {
	QHostAddress h = s->peerAddress();
	if (h.protocol() == QAbstractSocket::IPv4Protocol) {
		return h.toString()+QString(":")+QString::number(s->peerPort());
	}
	return QString("[")+h.toString()+QString("]:")+QString::number(s->peerPort());
}

