#include <QTest>
#include <QProcess>

#include <QTemporaryDir>
#include <QTemporaryFile>

class FileOpsTest : public QObject
{
	Q_OBJECT

private Q_SLOTS:
	void initTestCase();
	void cleanupTestCase();

	void testControlFile();
	void testLocalFileOps();
	void testArchiveOps();

private:
	QFile m_controlFile;
	QTemporaryDir m_mountDir;
};

void FileOpsTest::initTestCase()
{
	QString programpath = QFINDTESTDATA("kio-fuse");

	QProcess kiofuseProcess;
	kiofuseProcess.setProgram(programpath);
	kiofuseProcess.setArguments({m_mountDir.path()});

	kiofuseProcess.start();

	// kio-fuse without "-f" daemonizes only after mounting succeeded
	QVERIFY(kiofuseProcess.waitForFinished());
	QVERIFY(kiofuseProcess.exitStatus() == QProcess::NormalExit);
	QVERIFY(kiofuseProcess.exitCode() == 0);

	m_controlFile.setFileName(m_mountDir.filePath(QStringLiteral("_control")));

	QVERIFY(m_controlFile.open(QIODevice::WriteOnly | QIODevice::Unbuffered));
}

void FileOpsTest::cleanupTestCase()
{
	// Make sure that the mountpoint is not busy
	m_controlFile.close();

	QProcess fusermountProcess;
	fusermountProcess.start(QStringLiteral("fusermount3"), {QStringLiteral("-u"), m_mountDir.path()});

	// If any of this fails, we can't do anything anyway
	fusermountProcess.waitForFinished();
	m_mountDir.remove();
}

void FileOpsTest::testControlFile()
{
	QVERIFY(m_controlFile.exists());
	QVERIFY(m_controlFile.isWritable());

	QByteArray cmd = QStringLiteral("MOUNT invalid URL").toUtf8();
	QCOMPARE(m_controlFile.write(cmd), -1);
}

void FileOpsTest::testLocalFileOps()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());

	QCOMPARE(localFile.write("teststring"), 10);
	QVERIFY(localFile.flush());

	// Mount the temporary file
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localFile.fileName()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	// Doing the same again should work just fine
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QFile mirroredFile(QStringLiteral("%1/file%2").arg(m_mountDir.path()).arg(localFile.fileName()));
	QVERIFY(mirroredFile.exists());
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
	QCOMPARE(mirroredFile.size(), localFile.size());

	// Compare the content
	QVERIFY(localFile.seek(0));
	QCOMPARE(localFile.readAll(), mirroredFile.readAll());

	// Try again
	QVERIFY(localFile.seek(0));
	QVERIFY(mirroredFile.seek(0));
	QCOMPARE(localFile.readAll(), mirroredFile.readAll());

	// Again, but at an offset
	QVERIFY(localFile.seek(1));
	QVERIFY(mirroredFile.seek(1));
	QCOMPARE(localFile.readAll(), mirroredFile.readAll());

	// Mount the data path and compare the directory content
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	cmd = QStringLiteral("MOUNT file://%1").arg(dataPath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QString mirrordataPath = QStringLiteral("%1/file%2").arg(m_mountDir.path()).arg(dataPath);

	auto sourceEntryList = QDir(dataPath).entryList(QDir::NoFilter, QDir::Name);
	auto mirrorEntryList = QDir(mirrordataPath).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);
}

void FileOpsTest::testArchiveOps()
{
	QString outerpath = QFINDTESTDATA(QStringLiteral("data/outerarchive.tar.gz"));

	// Mount a file inside the archive
	QByteArray cmd = QStringLiteral("MOUNT tar://%1/outerarchive/outerfile").arg(outerpath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	// And verify its content
	QString outerfilepath = QStringLiteral("%1/tar%2/outerarchive/outerfile").arg(m_mountDir.path()).arg(outerpath);
	QFile outerfile(outerfilepath);
	QVERIFY(outerfile.open(QIODevice::ReadOnly));
	QCOMPARE(outerfile.readAll(), QStringLiteral("outercontent").toUtf8());

	// Next, mount an archive inside - this uses kio-fuse recursively
	cmd = QStringLiteral("MOUNT tar://%1/outerarchive/innerarchive.tar.gz").arg(outerpath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QString innerpath = QStringLiteral("%1/tar%2/outerarchive/innerarchive.tar.gz").arg(m_mountDir.path()).arg(outerpath);

	// Unfortunately kio_archive is not reentrant, so a direct access would deadlock.
	// As a workaround, cache the file to avoid a 2nd call into kio_archive.
	QFile innerarchiveFile(innerpath);
	QVERIFY(innerarchiveFile.open(QIODevice::ReadOnly));
	QVERIFY(!innerarchiveFile.readAll().isEmpty());

	QFile innerfile(QStringLiteral("%1/tar%2/innerarchive/innerfile").arg(m_mountDir.path()).arg(innerpath));
	QVERIFY(innerfile.open(QIODevice::ReadOnly));
	QCOMPARE(innerfile.readAll(), QStringLiteral("innercontent").toUtf8());
}

QTEST_GUILESS_MAIN(FileOpsTest)

#include "fileopstest.moc"
