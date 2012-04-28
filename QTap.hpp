#include <QObject>
#include <QSocketNotifier>

#define TAP_MAX_MTU 65535

class QTap: public QObject {
	Q_OBJECT;
public:
	QTap(const QString &pref_name = QString(), const QByteArray &mac = QByteArray(), QObject *parent = 0, int resume = -1);

	bool isValid() const;
	const QString &getName() const;
	int getFd() const;

	void setMac(const QByteArray &mac);

public slots:
	void activity(int);
	void write(const QByteArray&);

signals:
	void packet(const QByteArray &src_hw, const QByteArray &dst_hw, const QByteArray &data);

private:
	QString name;

	QSocketNotifier *notifier;
	int tap_fd;
};

