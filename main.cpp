#include <QCoreApplication>
#include <QDateTime>
#include "InVpn.hpp"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	// got a better seed?
	qsrand(QDateTime::currentMSecsSinceEpoch() & 0xffffffff);

	InVpn vpn;
	if (!vpn.isValid()) return 1;

	return app.exec();
}

