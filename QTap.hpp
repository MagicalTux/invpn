#include <QObject>
#include <QSocketNotifier>

#define TAP_MAX_MTU 65535

class QTap: public QObject {
	Q_OBJECT;
public:
	QTap(const QString &pref_name = QString());

	bool isValid() const;
	const QString &getName() const;

public slots:
	void activity(int);

signals:
	void packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data);

private:
	QString name;

	QSocketNotifier *notifier;
	int tap_fd;
};

