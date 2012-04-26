#include <QObject>
#include <QSqlDatabase>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslSocket>
#include <QTimer>
#include "QTap.hpp"
#include "InVpnSslServer.hpp"

class InVpnNode;

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

	void announce();

signals:
	void broadcast(const QByteArray&);

private:
	QTap *tap;
	InVpnSslServer *server;

	qint64 broadcastId();
	qint64 bc_last_id;

	QMap<QByteArray, InVpnNode*> nodes;

	QSqlDatabase db;

	QSslKey ssl_key;
	QSslCertificate ssl_cert;
	QList<QSslCertificate> ssl_ca;

	QByteArray mac;

	QTimer check;

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

