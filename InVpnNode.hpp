#include <QObject>

class QSslSocket;
class InVpn;

class InVpnNode: public QObject {
	Q_OBJECT;
public:
	InVpnNode(InVpn *parent, const QByteArray &mac);

	bool setLink(QSslSocket*);
	bool isLinked() const;

public slots:
	void push(const QByteArray&msg);

private:
	qint64 last_bcast;
	InVpn *parent;
	QByteArray mac;
	QSslSocket *link;
};

