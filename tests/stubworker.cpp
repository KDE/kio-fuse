/*
   SPDX-FileCopyrightText: 2026 Chinmoy Pradhan <chinmoy.pradhan@machinesoul.in>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

// A minimal stub KIO worker for testing kio-fuse against a remote protocol.

#include <sys/stat.h>

#include <QCoreApplication>
#include <QObject>
#include <QUrl>

#include <KIO/WorkerBase>

class StubWorker : public KIO::WorkerBase
{
public:
	StubWorker(const QByteArray &protocol, const QByteArray &pool, const QByteArray &app);

	KIO::WorkerResult stat(const QUrl &url) override;
	KIO::WorkerResult listDir(const QUrl &url) override;
	KIO::WorkerResult get(const QUrl &url) override;
};

class StubWorkerPluginForMetaData : public QObject
{
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "org.kde.kio.worker.stub" FILE "stubworker.json")
};

extern "C" {
int Q_DECL_EXPORT kdemain(int argc, char **argv)
{
	QCoreApplication app(argc, argv);
	app.setApplicationName(QStringLiteral("kio_stub"));

	if(argc != 4)
		return -1;

	StubWorker worker(argv[1], argv[2], argv[3]);
	worker.dispatchLoop();
	return 0;
}
}

StubWorker::StubWorker(const QByteArray &protocol,
                       const QByteArray &pool,
                       const QByteArray &app)
    : WorkerBase(protocol, pool, app)
{
}

KIO::WorkerResult StubWorker::stat(const QUrl &url)
{
	if(url.host().startsWith(QLatin1String("fail")))
		return KIO::WorkerResult::fail(KIO::ERR_DOES_NOT_EXIST, url.toString());

	const QString name = (url.path().isEmpty() || url.path() == QLatin1String("/"))
	                         ? QStringLiteral(".")
	                         : url.fileName();

	KIO::UDSEntry entry;
	entry.fastInsert(KIO::UDSEntry::UDS_NAME, name);
	entry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
	entry.fastInsert(KIO::UDSEntry::UDS_ACCESS, 0755);
	entry.fastInsert(KIO::UDSEntry::UDS_SIZE, 0);
	statEntry(entry);
	return KIO::WorkerResult::pass();
}

KIO::WorkerResult StubWorker::listDir(const QUrl &url)
{
	Q_UNUSED(url);

	KIO::UDSEntry dotEntry;
	dotEntry.fastInsert(KIO::UDSEntry::UDS_NAME, QStringLiteral("."));
	dotEntry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
	dotEntry.fastInsert(KIO::UDSEntry::UDS_ACCESS, 0755);
	dotEntry.fastInsert(KIO::UDSEntry::UDS_SIZE, 0);
	listEntry(dotEntry);

	for(const QString &name : { QStringLiteral("entry1.txt"), QStringLiteral("entry2.txt") })
	{
		KIO::UDSEntry entry;
		entry.fastInsert(KIO::UDSEntry::UDS_NAME, name);
		entry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFREG);
		entry.fastInsert(KIO::UDSEntry::UDS_ACCESS, 0644);
		entry.fastInsert(KIO::UDSEntry::UDS_SIZE, 0);
		listEntry(entry);
	}
	return KIO::WorkerResult::pass();
}

KIO::WorkerResult StubWorker::get(const QUrl &url)
{
	Q_UNUSED(url);
	mimeType(QStringLiteral("text/plain"));
	data(QByteArray());
	return KIO::WorkerResult::pass();
}

#include "stubworker.moc"
