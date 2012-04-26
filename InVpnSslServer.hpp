#include <QTcpServer>
#include <QSslSocket>

class InVpnSslServer: public QTcpServer {
	Q_OBJECT;
public:
	InVpnSslServer(QObject *parent=0): QTcpServer(parent) {};

signals:
	void ready(QSslSocket*);

protected:
	void incomingConnection(int);
};

