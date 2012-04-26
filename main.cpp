#include <QCoreApplication>
#include "QTap.hpp"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	QTap tap("invpn%d");
	if (!tap.isValid()) return 1;

	qDebug("got interface: %s", qPrintable(tap.getName()));

	return app.exec();
}

