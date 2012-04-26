#include <QObject>
#include <QSqlDatabase>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslSocket>
#include <QTimer>
#include "QTap.hpp"
#include "InVpnSslServer.hpp"

struct invpn_node_info {
	QByteArray mac;
	qint64 first_seen;
	qint64 last_seen;
	qint64 bcast_value;
	QString peer;
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
	void socketLost();

	void checkNodes();

private:
	QTap *tap;
	InVpnSslServer *server;

	qint64 broadcastId();
	qint64 bc_last_id;

	QMap<QByteArray, struct invpn_node_info*> nodes;
	QMap<QString, QSslSocket*> peers;

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

