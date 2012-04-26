#include <QObject>

class InVpnNode: public QObject {
	Q_OBJECT;
public:
	InVpnNode();

	bool setLink(QSslSocket*);
};

