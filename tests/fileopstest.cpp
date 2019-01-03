#include <unistd.h>

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
	QDateTime roundDownToSecond(QDateTime dt);

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

	// Compare file metadata
	QFileInfo localFileInfo(localFile.fileName()),
	          mirroredFileInfo(mirroredFile.fileName());

	QCOMPARE(mirroredFileInfo.size(), localFileInfo.size());
	// Not supported by KIO
	// QCOMPARE(mirroredFileInfo.metadataChangeTime(), localFileInfo.metadataChangeTime());
	// KIO does not expose times with sub-second precision
	QCOMPARE(mirroredFileInfo.lastModified(), roundDownToSecond(localFileInfo.lastModified()));
	QCOMPARE(mirroredFileInfo.lastRead(), roundDownToSecond(localFileInfo.lastRead()));

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

	// Write new data
	QVERIFY(mirroredFile.seek(0));
	QCOMPARE(mirroredFile.write(QStringLiteral("newteststring!").toUtf8()), 14);
	QVERIFY(mirroredFile.flush());
	// Flush the written contents into the backend
	QCOMPARE(fsync(mirroredFile.handle()), 0);

	// Currently, kio-fuse uses KIO::put and not KIO::write, so the file was replaced
	// instead of changed. So reopen the file.
	QFile localFile2(localFile.fileName());
	QVERIFY(localFile2.open(QIODevice::ReadOnly));

	// Compare the content
	QVERIFY(localFile2.seek(0));
	QVERIFY(mirroredFile.seek(0));
	QCOMPARE(localFile2.readAll(), mirroredFile.readAll());

	// Test truncation at open
	mirroredFile.close();
	QVERIFY(mirroredFile.open(QIODevice::WriteOnly | QIODevice::Truncate));
	QCOMPARE(mirroredFile.write(QStringLiteral("tststrng").toUtf8()), 8);
	QVERIFY(mirroredFile.flush());
	QCOMPARE(fsync(mirroredFile.handle()), 0); // Flush the written contents into the backend

	localFile2.close(); // Reopen the file, see above.
	QVERIFY(localFile2.open(QIODevice::ReadOnly));
	QCOMPARE(localFile2.readAll(), QStringLiteral("tststrng").toUtf8()); // Compare the content

	// Test manual truncation
	QCOMPARE(ftruncate(mirroredFile.handle(), 3), 0);
	QCOMPARE(fsync(mirroredFile.handle()), 0); // Flush the written contents into the backend

	localFile2.close(); // Reopen the file, see above.
	QVERIFY(localFile2.open(QIODevice::ReadOnly));
	QCOMPARE(localFile2.readAll(), QStringLiteral("tst").toUtf8()); // Compare the content

	// Mount the data path and compare the directory content
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	cmd = QStringLiteral("MOUNT file://%1").arg(dataPath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QString mirrordataPath = QStringLiteral("%1/file%2").arg(m_mountDir.path()).arg(dataPath);

	auto sourceEntryList = QDir(dataPath).entryList(QDir::NoFilter, QDir::Name);
	auto mirrorEntryList = QDir(mirrordataPath).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);

	// Make sure dirlisting file:/// works
	sourceEntryList = QDir(QStringLiteral("/")).entryList(QDir::NoFilter, QDir::Name);
	mirrorEntryList = QDir(QStringLiteral("%1/file").arg(m_mountDir.path())).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);

	QFile symlink(QDir(dataPath).filePath(QStringLiteral("symlink")));

	QVERIFY(symlink.open(QIODevice::ReadOnly));
	QCOMPARE(symlink.readAll(), QStringLiteral("symlinktargetcontent").toUtf8());
	QCOMPARE(symlink.symLinkTarget(), QDir(dataPath).filePath(QStringLiteral("symlinktarget")));
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

	QString innerpath = QStringLiteral("%1/tar%2/outerarchive/innerarchive.tar.gz").arg(m_mountDir.path()).arg(outerpath);

	// Unfortunately kio_archive is not reentrant, so a direct access would deadlock.
	// As a workaround, cache the file to avoid a 2nd call into kio_archive.
	QFile innerarchiveFile(innerpath);
	QVERIFY(innerarchiveFile.open(QIODevice::ReadOnly));
	QVERIFY(!innerarchiveFile.readAll().isEmpty());

	// Next, mount an archive inside - this uses kio-fuse recursively
	cmd = QStringLiteral("MOUNT tar://%1").arg(innerpath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QFile innerfile(QStringLiteral("%1/tar%2/innerarchive/innerfile").arg(m_mountDir.path()).arg(innerpath));
	QVERIFY(innerfile.open(QIODevice::ReadOnly));
	QCOMPARE(innerfile.readAll(), QStringLiteral("innercontent").toUtf8());
}

QDateTime FileOpsTest::roundDownToSecond(QDateTime dt)
{
	return QDateTime::fromTime_t(dt.toTime_t());
}

QTEST_GUILESS_MAIN(FileOpsTest)

#include "fileopstest.moc"
