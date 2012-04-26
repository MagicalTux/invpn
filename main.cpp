#include <QCoreApplication>
#include "QTap.hpp"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	QTap tap;

	return app.exec();
}

