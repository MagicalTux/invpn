#include <QObject>
#include <QAbstractSocket>

class QSslSocket;
class InVpn;

class InVpnNode: public QObject {
	Q_OBJECT;
public:
	InVpnNode(InVpn *parent, const QByteArray &mac);

	bool setLink(QSslSocket*);
	bool isLinked() const;

	bool checkStamp(qint64);

public slots:
	void push(const QByteArray&msg);
	void socketRead();
	void socketLost();
	void socketError(QAbstractSocket::SocketError);

private:
	void handlePacket(const QByteArray&pkt);

	qint64 last_bcast;
	InVpn *parent;
	QByteArray mac;
	QSslSocket *link;

	QByteArray readbuf;
};

