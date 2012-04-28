#include <QCoreApplication>
#include <QDateTime>
#include <QMetaObject>
#include <signal.h>
#include "InVpn.hpp"

static InVpn *_glob;

static void signal_prog_end(int, siginfo_t *, void *) {
	QMetaObject::invokeMethod(_glob, "quit", Qt::QueuedConnection);
}

static void signal_prog_restart(int, siginfo_t *, void *) {
	QMetaObject::invokeMethod(_glob, "restart", Qt::QueuedConnection);
}

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	// got a better seed?
	qsrand(QDateTime::currentMSecsSinceEpoch() & 0xffffffff);

	InVpn vpn;
	if (!vpn.isValid()) return 1;
	_glob = &vpn;

	// catch signals, send to Qt object by using Qt::QueuedConnection
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;

	sa.sa_sigaction = signal_prog_end;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sa.sa_sigaction = signal_prog_restart;
	sigaction(SIGUSR2, &sa, NULL);

	return app.exec();
}

