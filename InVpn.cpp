#include "InVpn.hpp"
#include <QCoreApplication>
#include <QStringList>
#include <QFile>
#include <QSslConfiguration>

InVpn::InVpn() {
	tap = NULL;
	parseCmdLine();

	// initialize DB
	db = QSqlDatabase::addDatabase("QSQLITE");
	db.setDatabaseName(db_path);
	if (!db.open()) {
		qDebug("Could not open database");
		QCoreApplication::exit(1);
		return;
	}

	// initialize SSL
	QFile key_file(key_path);
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
	ssl_cert = QSslCertificate::fromPath(cert_path, QSsl::Pem, QRegExp::FixedString).at(0);
	ssl_ca = QSslCertificate::fromPath(ca_path, QSsl::Pem);

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

	tap = new QTap("invpn%d", this);
	if (!tap->isValid()) {
		delete tap;
		tap = NULL;
		return;
	}
	tap->setMac(mac);

	connect(tap, SIGNAL(packet(const QByteArray&, const QByteArray&, const QByteArray&)), this, SLOT(packet(const QByteArray&, const QByteArray&, const QByteArray&)));

	qDebug("got interface: %s", qPrintable(tap->getName()));
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
	qDebug("packet data: [%s] => [%s] %s", src_hw.toHex().constData(), dst_hw.toHex().constData(), data.toHex().constData());
}

void InVpn::parseCmdLine() {
	// set default settings, then try to parse cmdline
	port = 41744;
	key_path = "conf/client.key";
	cert_path = "conf/client.crt";
	ca_path = "conf/ca.crt";
	db_path = "conf/client.db";

	QStringList cmdline = QCoreApplication::arguments();

	// Why isn't there a cmdline parser included with Qt? ;_;
	for(int i = 1; i < cmdline.size(); i++) {
		QString tmp = cmdline.at(i);
		if (tmp == "-k") {
			key_path = cmdline.at(i+1); i++; continue;
		}
		if (tmp == "-c") {
			cert_path = cmdline.at(i+1); i++; continue;
		}
		if (tmp == "-a") {
			ca_path = cmdline.at(i+1); i++; continue;
		}
		if (tmp == "-s") {
			db_path = cmdline.at(i+1); i++; continue;
		}
		if (tmp == "-p") {
			port = cmdline.at(i+1).toInt(); i++; continue;
		}
		// ignore unrecognized args
	}
}

