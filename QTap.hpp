#include <QObject>
#include <QSocketNotifier>

class QTap: public QObject {
	Q_OBJECT;
public:
	QTap();

private:
	QString name;

	QSocketNotifier *notifier;
	int tap_fd;
};

