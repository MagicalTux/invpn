#include <QObject>
#include <QSqlDatabase>
#include <QSslKey>
#include <QSslCertificate>
#include "QTap.hpp"

class InVpn: public QObject {
	Q_OBJECT;
public:
	InVpn();

public slots:
	void packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data);

private:
	QTap *tap;

	QSqlDatabase db;

	QSslKey ssl_key;
	QSslCertificate ssl_cert;
	QList<QSslCertificate> ssl_ca;

	QByteArray mac;

	// settings
	void parseCmdLine();
	QString key_path;
	QString cert_path;
	QString ca_path;
	QString db_path;
	int port;
};

