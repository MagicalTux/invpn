#include <QCoreApplication>
#include "InVpn.hpp"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	InVpn vpn;
	if (!vpn.isValid()) return 1;

	return app.exec();
}

