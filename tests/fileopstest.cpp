/*
 * Copyright 2019 Fabian Vogt <fabian@ritter-vogt.de>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License or any later version accepted by the membership of
 * KDE e.V. (or its successor approved by the membership of KDE
 * e.V.), which shall act as a proxy defined in Section 14 of
 * version 3 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QTest>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusReply>
#include <QDebug>
#include "kiofuse_interface.h"
#include "kiofuseprivate_interface.h"

class FileOpsTest : public QObject
{
	Q_OBJECT

private Q_SLOTS:
	void initTestCase();
	void cleanupTestCase();

	void testDBusErrorReply();
	void testLocalPathToRemoteUrl();
	void testLocalFileOps();
	void testLocalDirOps();
	void testCreationOps();
	void testRenameOps();
	void testDeletionOps();
	void testArchiveOps();
	void testKioErrorMapping();
	void testRootLookup();
	void testFilenameEscaping();
	void testDirRefresh();
	void testFileRefresh();
	void testSymlinkRefresh();
	void testTypeRefresh();
#ifdef WASTE_DISK_SPACE
	void testReadWrite4GBFile();
#endif // WASTE_DISK_SPACE

private:
	QDateTime roundDownToSecond(QDateTime dt);
	bool forceNodeTimeout();

	org::kde::KIOFuse::VFS m_kiofuse_iface{QStringLiteral("org.kde.KIOFuse"),
		                                   QStringLiteral("/org/kde/KIOFuse"),
		                                   QDBusConnection::sessionBus()};
	org::kde::KIOFuse::Private m_kiofuseprivate_iface{QStringLiteral("org.kde.KIOFuse"),
		                                              QStringLiteral("/org/kde/KIOFuse"),
		                                              QDBusConnection::sessionBus()};
	QTemporaryDir m_mountDir;
};

void FileOpsTest::initTestCase()
{
	// QTemporaryDir would otherwise rm -rf on destruction,
	// which is fatal if umount fails while something is mounted inside
	m_mountDir.setAutoRemove(false);
	QString programpath = QFINDTESTDATA("kio-fuse");

	QProcess kiofuseProcess;
	kiofuseProcess.setProgram(programpath);
#ifdef TEST_CACHE_BASED_IO
	kiofuseProcess.setArguments(QStringList() << m_mountDir.path() << QStringLiteral("--disable-filejob-io"));
#else
	kiofuseProcess.setArguments({m_mountDir.path()});
#endif
	kiofuseProcess.setProcessChannelMode(QProcess::ForwardedChannels);

	kiofuseProcess.start();
	QVERIFY(kiofuseProcess.waitForFinished());
	QCOMPARE(kiofuseProcess.exitStatus(),  QProcess::NormalExit);
	QCOMPARE(kiofuseProcess.exitCode(), 0);
}

void FileOpsTest::cleanupTestCase()
{
	QProcess unmountProcess;
	#ifdef Q_OS_FREEBSD
		// No fusermount on FreeBSD, use umount directly instead
		unmountProcess.start(QStringLiteral("umount"), {m_mountDir.path()});
	#else
		unmountProcess.start(QStringLiteral("fusermount3"), {QStringLiteral("-u"), m_mountDir.path()});
	#endif

	QVERIFY(unmountProcess.waitForFinished());
	QCOMPARE(unmountProcess.exitStatus(), QProcess::NormalExit);
	QCOMPARE(unmountProcess.exitCode(), 0);

	// Remove only after umounting suceeded
	m_mountDir.remove();
}

void FileOpsTest::testDBusErrorReply()
{
	QDBusPendingReply<QString> reply = m_kiofuse_iface.mountUrl(QStringLiteral("invalid URL"));
	reply.waitForFinished();
	QVERIFY(reply.isError());
	QCOMPARE(reply.error().name(), QStringLiteral("org.kde.KIOFuse.VFS.Error.CannotMount"));

	reply = m_kiofuse_iface.mountUrl(QStringLiteral("http://www.kde.org"));
	reply.waitForFinished();
	QVERIFY(reply.isError());
	QCOMPARE(reply.error().name(), QStringLiteral("org.kde.KIOFuse.VFS.Error.SchemeNotSupported"));
}

void FileOpsTest::testLocalPathToRemoteUrl()
{
	QDBusPendingReply<QString> errorReply;
	// mtp:/ -> Remote URL can't possibly be location of KIOFuse mount.
	// / -> Root can't possibly be location of KIOFuse mount.
	// m_mountDir -> Whilst this is in the KIOFuse mount, no remote URL exists for it
	for(auto url : {QStringLiteral("mtp:/"), QStringLiteral("/"), m_mountDir.path()})
	{
		errorReply = m_kiofuse_iface.remoteUrl(url);
		errorReply.waitForFinished();
		QVERIFY2(errorReply.isError(), qPrintable(url));
		QCOMPARE(errorReply.error().name(), QStringLiteral("org.kde.KIOFuse.VFS.Error.RemoteURLNotFound"));
	}

	QTemporaryFile localFile;
	QVERIFY(localFile.open());
	localFile.close(); // Force creation of file to avoid empty fileName()
	QString remoteUrl = QStringLiteral("file://%1").arg(localFile.fileName());
	QString reply = m_kiofuse_iface.mountUrl(remoteUrl).value();
	QVERIFY(!reply.isEmpty());
	QString calculatedRemoteUrl = m_kiofuse_iface.remoteUrl(reply).value();
	QCOMPARE(remoteUrl, calculatedRemoteUrl);
}

void FileOpsTest::testLocalFileOps()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());

	QCOMPARE(localFile.write("teststring"), 10);
	QVERIFY(localFile.flush());

	// Mount the temporary file
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localFile.fileName())).value();
	QVERIFY(!reply.isEmpty());

	// Doing the same again should work just fine
	reply = m_kiofuse_iface.mountUrl(localFile.fileName()).value();
	QVERIFY(!reply.isEmpty());

	QFile mirroredFile(reply);
	QVERIFY(mirroredFile.exists());
	QCOMPARE(mirroredFile.size(), localFile.size());

	// Compare file metadata
	QFileInfo localFileInfo(localFile),
	          mirroredFileInfo(mirroredFile);

	QCOMPARE(mirroredFileInfo.size(), localFileInfo.size());
	QCOMPARE(mirroredFileInfo.ownerId(), localFileInfo.ownerId());
	QCOMPARE(mirroredFileInfo.groupId(), localFileInfo.groupId());
	// Not supported by KIO
	// QCOMPARE(mirroredFileInfo.metadataChangeTime(), localFileInfo.metadataChangeTime());
	// KIO does not expose times with sub-second precision
	QCOMPARE(mirroredFileInfo.lastModified(), roundDownToSecond(localFileInfo.lastModified()));
	QCOMPARE(mirroredFileInfo.lastRead(), roundDownToSecond(localFileInfo.lastRead()));

	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
	// Test touching the file
	struct timespec times[2] = {{time_t(localFileInfo.lastModified().toSecsSinceEpoch()) + 42, 0},
	                            {time_t(localFileInfo.lastRead().toSecsSinceEpoch()) + 1, 0}};
	QCOMPARE(futimens(mirroredFile.handle(), times), 0);
	localFileInfo.refresh();
	mirroredFileInfo.refresh();
	QCOMPARE(mirroredFileInfo.lastModified().toSecsSinceEpoch(), times[1].tv_sec);
	QCOMPARE(localFileInfo.lastModified().toSecsSinceEpoch(), times[1].tv_sec);
	// Access time not supported on the remote side, so only check in the mirror
	QCOMPARE(mirroredFileInfo.lastRead().toSecsSinceEpoch(), times[0].tv_sec);
	//QCOMPARE(localFileInfo.lastRead().toSecsSinceEpoch(), times[0].tv_sec);

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

	// Write new data, but close the file instead of flushing
	QVERIFY(mirroredFile.seek(0));
	QCOMPARE(mirroredFile.write(QStringLiteral("differentteststring").toUtf8()), 19);
	mirroredFile.close();
	localFile2.close();
	QVERIFY(localFile2.open(QIODevice::ReadOnly));
	QVERIFY(localFile2.seek(0));
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
	QVERIFY(mirroredFile.seek(0));
	QCOMPARE(localFile2.readAll(), QStringLiteral("differentteststring").toUtf8());

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

	// Test chown by not changing anything (no CAP_CHOWN...)
	QCOMPARE(chown(mirroredFile.fileName().toUtf8().data(), getuid(), getgid()), 0);
	localFileInfo.refresh();
	QCOMPARE(localFileInfo.ownerId(), getuid());
	QCOMPARE(localFileInfo.groupId(), getgid());
	// Should not be allowed
	QCOMPARE(chown(mirroredFile.fileName().toUtf8().data(), getuid(), 0), -1);
	QCOMPARE(chown(mirroredFile.fileName().toUtf8().data(), 0, getgid()), -1);

	// Test chmod
	QCOMPARE(chmod(mirroredFile.fileName().toUtf8().data(), 0054), 0);
	struct stat attr;
	QCOMPARE(stat(localFile.fileName().toUtf8().data(), &attr), 0);
	QCOMPARE(attr.st_mode, S_IFREG | 0054);
	QCOMPARE(chmod(mirroredFile.fileName().toUtf8().data(), 0600), 0);
	QCOMPARE(stat(localFile.fileName().toUtf8().data(), &attr), 0);
	QCOMPARE(attr.st_mode, S_IFREG | 0600);

	// Mount the data path
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(dataPath)).value();
	QVERIFY(!reply.isEmpty());
	QString mirrordataPath = reply;

	// Verify the symlink inside is correct
	QFile symlink(QDir(mirrordataPath).filePath(QStringLiteral("symlink")));

	QVERIFY(symlink.open(QIODevice::ReadOnly));
	QCOMPARE(symlink.readAll(), QStringLiteral("symlinktargetcontent").toUtf8());
	QCOMPARE(symlink.symLinkTarget(), QDir(mirrordataPath).filePath(QStringLiteral("symlinktarget")));
	
	// Verify that we adhere to O_APPEND flag as kernel doesn't handle this for us.
	QTemporaryFile appendFile;
	QVERIFY(appendFile.open());
	QCOMPARE(appendFile.write("teststring"), 10);
	QVERIFY(appendFile.flush());
	appendFile.close();
	// Mount the temp file
	reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(appendFile.fileName())).value();
	QVERIFY(!reply.isEmpty());

	QFile appendMirror(reply);
	QVERIFY(appendMirror.exists());
	QVERIFY(appendMirror.open(QIODevice::Append | QIODevice::ReadWrite));
	// even if we set seek to 0 kio-fuse should change it back to the end of the file.
	QVERIFY(appendMirror.seek(0));
	QCOMPARE(appendMirror.write("APPENDME"), 8);
	// Pass changes from mirror to local.
	QVERIFY(appendMirror.flush());
	QCOMPARE(fsync(appendMirror.handle()), 0);
	
	// Currently, kio-fuse uses KIO::put and not KIO::write, so the file was replaced
	// instead of changed. So reopen the file.
	QFile appendFile2(appendFile.fileName());
	QVERIFY(appendFile2.open(QIODevice::ReadOnly));
	QVERIFY(appendMirror.seek(0));
	QVERIFY(appendFile2.seek(0));
	// If we don't adhere to O_APPEND flag we'd get "APPENDMEng" instead...
	QCOMPARE(appendMirror.readAll(), QStringLiteral("teststringAPPENDME").toUtf8());
	QVERIFY(appendMirror.seek(0));
	QVERIFY(appendFile2.seek(0));
	QCOMPARE(appendMirror.readAll(), appendFile2.readAll());
}

void FileOpsTest::testLocalDirOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a folder inside
	QVERIFY(mirrorDir.mkdir(QStringLiteral("directory")));
	QVERIFY(QFile::exists(localDir.filePath(QStringLiteral("directory"))));

	// Compare file metadata
	QFileInfo localDirInfo(localDir.path()),
	          mirrorDirInfo(mirrorDir.path());

	QCOMPARE(mirrorDirInfo.ownerId(), localDirInfo.ownerId());
	QCOMPARE(mirrorDirInfo.groupId(), localDirInfo.groupId());
	// Not supported by KIO
	// QCOMPARE(mirroredFileInfo.metadataChangeTime(), localFileInfo.metadataChangeTime());
	// KIO does not expose times with sub-second precision
	QCOMPARE(mirrorDirInfo.lastModified(), roundDownToSecond(localDirInfo.lastModified()));
	QCOMPARE(mirrorDirInfo.lastRead(), roundDownToSecond(localDirInfo.lastRead()));

	// Test touching the file
	struct timespec times[2] = {{time_t(localDirInfo.lastModified().toSecsSinceEpoch()) + 42, 0},
	                            {time_t(localDirInfo.lastRead().toSecsSinceEpoch()) + 1, 0}};
	QCOMPARE(utimensat(AT_FDCWD, mirrorDir.path().toUtf8().data(), times, 0), 0);
	localDirInfo.refresh();
	mirrorDirInfo.refresh();
	QCOMPARE(mirrorDirInfo.lastModified().toSecsSinceEpoch(), times[1].tv_sec);
	QCOMPARE(localDirInfo.lastModified().toSecsSinceEpoch(), times[1].tv_sec);
	// Access time not supported on the remote side, so only check in the mirror
	QCOMPARE(mirrorDirInfo.lastRead().toSecsSinceEpoch(), times[0].tv_sec);
	//QCOMPARE(localDirInfo.lastRead().toSecsSinceEpoch(), times[0].tv_sec);

	// Test chown by not changing anything (no CAP_CHOWN...)
	QCOMPARE(chown(mirrorDir.path().toUtf8().data(), getuid(), getgid()), 0);
	localDirInfo.refresh();
	QCOMPARE(localDirInfo.ownerId(), getuid());
	QCOMPARE(localDirInfo.groupId(), getgid());
	// Should not be allowed
	QCOMPARE(chown(mirrorDir.path().toUtf8().data(), getuid(), 0), -1);
	QCOMPARE(chown(mirrorDir.path().toUtf8().data(), 0, getgid()), -1);

	// Test chmod
	QCOMPARE(chmod(mirrorDir.path().toUtf8().data(), 0054), 0);
	struct stat attr;
	QCOMPARE(stat(localDir.path().toUtf8().data(), &attr), 0);
	QCOMPARE(attr.st_mode, S_IFDIR | 0054);
	QCOMPARE(chmod(mirrorDir.path().toUtf8().data(), 0700), 0);
	QCOMPARE(stat(localDir.path().toUtf8().data(), &attr), 0);
	QCOMPARE(attr.st_mode, S_IFDIR | 0700);

	// Mount the data path and compare the directory content
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(dataPath)).value();
	QVERIFY(!reply.isEmpty());
	QString mirrordataPath = reply;

	auto sourceEntryList = QDir(dataPath).entryList(QDir::NoFilter, QDir::Name);
	auto mirrorEntryList = QDir(mirrordataPath).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);

	// Make sure dirlisting file:/// works
	sourceEntryList = QDir(QStringLiteral("/")).entryList(QDir::NoFilter, QDir::Name);
	reply = m_kiofuse_iface.mountUrl(QStringLiteral("file:///")).value();
	QVERIFY(!reply.isEmpty());
	mirrorEntryList = QDir(reply).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);
}

void FileOpsTest::testCreationOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a symlink
	QCOMPARE(symlink("target", mirrorDir.filePath(QStringLiteral("symlink")).toUtf8().data()), 0);
	QCOMPARE(QFileInfo(localDir.filePath(QStringLiteral("symlink"))).symLinkTarget(), localDir.filePath(QStringLiteral("target")));

	// Create a regular file
	QFile newFile(mirrorDir.filePath(QStringLiteral("newFile")));
	QVERIFY(newFile.open(QIODevice::ReadWrite));

	QFile newFileLocal(localDir.filePath(QStringLiteral("newFile")));
	QVERIFY(newFileLocal.exists());
	QCOMPARE(newFileLocal.size(), 0);

	QVERIFY(newFile.write(QStringLiteral("someweirdstring").toUtf8()));
	QVERIFY(newFile.flush());
	QCOMPARE(fsync(newFile.handle()), 0);

	// Reopen the file (see above in testLocalFileOps)
	newFileLocal.close();
	QVERIFY(newFileLocal.open(QIODevice::ReadOnly));
	QCOMPARE(newFileLocal.readAll(), QStringLiteral("someweirdstring").toUtf8());
}

void FileOpsTest::testRenameOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a directory
	QVERIFY(QDir(mirrorDir.path()).mkdir(QStringLiteral("dira")));
	QDir dir(mirrorDir.filePath(QStringLiteral("dira")));

	// And a file inside
	QFile file(dir.filePath(QStringLiteral("filea")));
	QVERIFY(file.open(QIODevice::ReadWrite));
	QVERIFY(file.write(QStringLiteral("someweirdstring").toUtf8()));

	// Note: QFile::rename copies and unlinks if the rename syscall fails,
	// so use the libc function directly

	// Rename the file
	QCOMPARE(rename(dir.filePath(QStringLiteral("filea")).toUtf8().data(),
	                dir.filePath(QStringLiteral("fileb")).toUtf8().data()), 0);
	QVERIFY(!QFile::exists(dir.filePath(QStringLiteral("filea"))));
	QVERIFY(QFile::exists(dir.filePath(QStringLiteral("fileb"))));
	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dira/filea"))));
	QVERIFY(QFile::exists(localDir.filePath(QStringLiteral("dira/fileb"))));

	// Rename the directory
	QCOMPARE(rename(mirrorDir.filePath(QStringLiteral("dira")).toUtf8().data(),
	                mirrorDir.filePath(QStringLiteral("dirb")).toUtf8().data()), 0);
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("dira"))));
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("dirb"))));
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("dira"))));
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("dirb"))));
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/filea"))));
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/fileb"))));

	// Verify that the file is still open and "connected"
	QVERIFY(file.write(QStringLiteral("!").toUtf8()));
	QVERIFY(file.flush());
	QCOMPARE(fsync(file.handle()), 0);
	QFile localFile(localDir.filePath(QStringLiteral("dirb/fileb")));
	QVERIFY(localFile.open(QIODevice::ReadOnly));
	QCOMPARE(localFile.readAll(), QStringLiteral("someweirdstring!").toUtf8());

	// Try the same, but overwriting an existing file
	QFile overwrittenFile(mirrorDir.filePath(QStringLiteral("dirb/filec")));
	QVERIFY(overwrittenFile.open(QIODevice::ReadWrite));
	QCOMPARE(overwrittenFile.write(QStringLiteral("data").toUtf8()), 4);
	QVERIFY(overwrittenFile.flush());
#ifdef RENAME_NOREPLACE
	QCOMPARE(renameat2(AT_FDCWD, mirrorDir.filePath(QStringLiteral("dirb/fileb")).toUtf8().data(),
	                   AT_FDCWD, mirrorDir.filePath(QStringLiteral("dirb/filec")).toUtf8().data(),
	                   RENAME_NOREPLACE), -1);
	QCOMPARE(errno, EEXIST);
#endif

	QCOMPARE(rename(mirrorDir.filePath(QStringLiteral("dirb/fileb")).toUtf8().data(),
	                mirrorDir.filePath(QStringLiteral("dirb/filec")).toUtf8().data()), 0);
	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dirb/fileb"))));
	QVERIFY(QFile::exists(localDir.filePath(QStringLiteral("dirb/filec"))));
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/fileb"))));
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/filec"))));

	QVERIFY(overwrittenFile.seek(0));
#ifdef TEST_CACHE_BASED_IO
	// Both handles must still be valid
	QCOMPARE(overwrittenFile.readAll(), QStringLiteral("data").toUtf8());
#else
	// Doesn't apply to FileJob (KIO::open) I/O
	QCOMPARE(overwrittenFile.readAll(), QStringLiteral("").toUtf8());
#endif

	localFile.close();
	localFile.setFileName(localDir.filePath(QStringLiteral("dirb/filec")));
	QVERIFY(localFile.open(QIODevice::ReadOnly));
	QCOMPARE(localFile.readAll(), QStringLiteral("someweirdstring!").toUtf8());
}

void FileOpsTest::testDeletionOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a directory
	QVERIFY(QDir(mirrorDir.path()).mkdir(QStringLiteral("dir")));
	QDir dir(mirrorDir.filePath(QStringLiteral("dir")));

	// And a file inside
	QFile file(dir.filePath(QStringLiteral("file")));
	QVERIFY(file.open(QIODevice::ReadWrite));
	QVERIFY(file.write(QStringLiteral("someweirdstring").toUtf8()));
	QVERIFY(file.flush());

	// Try to delete the directory
	QCOMPARE(unlink(dir.path().toUtf8().data()), -1);
	#ifdef Q_OS_LINUX
		QCOMPARE(errno, EISDIR);
	#else
		QCOMPARE(errno, EPERM);
	#endif
	QCOMPARE(rmdir(dir.path().toUtf8().data()), -1);
	QCOMPARE(errno, ENOTEMPTY);

#ifdef TEST_CACHE_BASED_IO
	// Delete the file
	QCOMPARE(rmdir(file.fileName().toUtf8().data()), -1);
	QCOMPARE(errno, ENOTDIR);
	QCOMPARE(unlink(file.fileName().toUtf8().data()), 0);
	QVERIFY(!file.exists());
	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dir/file"))));

	// Make sure it's still open
	QVERIFY(file.seek(0));
	QCOMPARE(file.readAll(), QStringLiteral("someweirdstring").toUtf8());

	// Delete the now empty directory
	QCOMPARE(rmdir(dir.path().toUtf8().data()), 0);
	QVERIFY(!dir.exists());
	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dir"))));

	// Make sure the file is still open
	QVERIFY(file.seek(0));
	QCOMPARE(file.readAll(), QStringLiteral("someweirdstring").toUtf8());
#else
	// FileJob-based nodes only unlink if the file isn't open
	QCOMPARE(rmdir(file.fileName().toUtf8().data()), -1);
	QCOMPARE(errno, ENOTDIR);
	QCOMPARE(unlink(file.fileName().toUtf8().data()), -1);
	file.close();
	QCOMPARE(unlink(file.fileName().toUtf8().data()), 0);
	QVERIFY(!file.exists());
	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dir/file"))));
#endif


	// Not implemented: Link the file back into the tree, if possible
	// QCOMPARE(link(QStringLiteral("/proc/self/fd/%1").arg(file.handle()).toUtf8().data(),
	//              mirrorDir.filePath(QStringLiteral("deletedFile")).toUtf8().data()), 0);
	// ... test that the file is still open and connected.
}

void FileOpsTest::testArchiveOps()
{
	QString outerpath = QFINDTESTDATA(QStringLiteral("data/outerarchive.tar.gz"));

	// Mount a file inside the archive
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("tar://%1/outerarchive/outerfile").arg(outerpath)).value();
	QVERIFY(!reply.isEmpty());

	// And verify its content
	QString outerfilepath = reply;
	QFile outerfile(outerfilepath);
	QVERIFY(outerfile.open(QIODevice::ReadOnly));
	QCOMPARE(outerfile.readAll(), QStringLiteral("outercontent").toUtf8());

	reply = m_kiofuse_iface.mountUrl(QStringLiteral("tar://%1/outerarchive/innerarchive.tar.gz").arg(outerpath)).value();
	QVERIFY(!reply.isEmpty());
	QString innerpath = reply;

	// Unfortunately kio_archive is not reentrant, so a direct access would deadlock.
	// As a workaround, cache the file to avoid a 2nd call into kio_archive.
	QFile innerarchiveFile(innerpath);
	QVERIFY(innerarchiveFile.open(QIODevice::ReadOnly));
	QVERIFY(!innerarchiveFile.readAll().isEmpty());

	// Next, mount an archive inside - this uses kio-fuse recursively
	reply = m_kiofuse_iface.mountUrl(QStringLiteral("tar://%1").arg(innerpath)).value();
	QVERIFY(!reply.isEmpty());

	QFile innerfile(QStringLiteral("%1/innerarchive/innerfile").arg(reply));
	QVERIFY(innerfile.open(QIODevice::ReadOnly));
	QCOMPARE(innerfile.readAll(), QStringLiteral("innercontent").toUtf8());
}

void FileOpsTest::testKioErrorMapping()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());
	
	// Mount the temporary file
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localFile.fileName())).value();
	QVERIFY(!reply.isEmpty());
	
	QFile mirroredFile(reply);
	QVERIFY(mirroredFile.exists());
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
	QCOMPARE(mirroredFile.size(), localFile.size());
	// No permission to chown to root/root (unless running with CAP_CHOWN or being root)
	QCOMPARE(chown(mirroredFile.fileName().toUtf8().data(), 0, 0), -1);
	QCOMPARE(errno, EPERM);
}

void FileOpsTest::testRootLookup()
{
	struct stat st;
	// Verify that it does not exist...
	QCOMPARE(stat(qPrintable(QStringLiteral("%1/invalid").arg(m_mountDir.path())), &st), -1);
	// ... and set errno correctly
	QCOMPARE(errno, ENOENT);
}

void FileOpsTest::testFilenameEscaping()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a file in localDir with an "unusual" filename
	for(const QString &name : {QStringLiteral("file0?name"),
	    QStringLiteral("file1#name"), QStringLiteral("file2%20name"),
	    QStringLiteral("file2 \nname?asdf&foo#bar")})
	{
		QFile localFile(localDir.filePath(name));
		QVERIFY(localFile.open(QFile::WriteOnly));
		QCOMPARE(localFile.write("teststring", 10), 10);
		localFile.close();

		QFile mirrorFile(mirrorDir.filePath(name));
		QVERIFY2(mirrorFile.open(QFile::ReadOnly), name.toUtf8().data());
		QCOMPARE(mirrorFile.readAll(), QStringLiteral("teststring").toUtf8());
	}
}

void FileOpsTest::testDirRefresh()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// readdir must not have any content yet
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot).count(), 0);

	QFile newFile(localDir.filePath(QStringLiteral("newFile")));
	QVERIFY(newFile.open(QFile::ReadWrite));

	// Verify that the file is part of a dirlist after refresh
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot).count(), 0);
	QVERIFY(forceNodeTimeout());
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot),
	         QStringList{QStringLiteral("newFile")});

	// Delete the file
	newFile.close();
	QVERIFY(newFile.remove());

	// Verify that it disappears from the dirlist after refresh
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot), QStringList{QStringLiteral("newFile")});
	QVERIFY(forceNodeTimeout());
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot).count(), 0);

	// Recreate the file
	QVERIFY(newFile.open(QFile::ReadWrite));

	// Verify that access is immediately possible again (lookup is "optimistic")
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("newFile"))));

	// Delete the file again
	newFile.close();
	QVERIFY(newFile.remove());

	// Verify that after a refresh it's dropped
	QVERIFY(forceNodeTimeout());
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("newFile"))));
}

void FileOpsTest::testFileRefresh()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// readdir must not have any content yet
	QCOMPARE(mirrorDir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot).count(), 0);

	QFile localFile(localDir.filePath(QStringLiteral("newFile")));
	QVERIFY(localFile.open(QFile::ReadWrite));

	QFile mirrorFile(mirrorDir.filePath(QStringLiteral("newFile")));
	QVERIFY(mirrorFile.open(QFile::ReadOnly));
	QCOMPARE(mirrorFile.size(), 0); // File is empty
	QCOMPARE(mirrorFile.readAll(), QByteArray{});
	QVERIFY(mirrorFile.permissions() & QFile::ReadOther); // Has default perms

	QCOMPARE(localFile.write("teststring", 10), 10); // Write some data
	QVERIFY(localFile.flush());
	QVERIFY(localFile.setPermissions(localFile.permissions() & ~QFile::ReadOther)); // Change perms
	QCOMPARE(mirrorFile.size(), 0); // File is still empty
	QVERIFY(forceNodeTimeout());

	// Without reopening, it has the new content and perms now
	QCOMPARE(mirrorFile.size(), 10);
	QCOMPARE(mirrorFile.readAll(), QStringLiteral("teststring").toUtf8());
	QCOMPARE(mirrorFile.permissions() & QFile::ReadOther, 0); // Has changed perms
}

void FileOpsTest::testSymlinkRefresh()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a symlink
	QCOMPARE(symlink("/oldtarget", localDir.filePath(QStringLiteral("symlink")).toUtf8().data()), 0);
	QCOMPARE(QFile::symLinkTarget(mirrorDir.filePath(QStringLiteral("symlink"))), QStringLiteral("/oldtarget"));

	// Change the symlink
	QVERIFY(QFile::remove(localDir.filePath((QStringLiteral("symlink")))));
	QCOMPARE(symlink("/newtarget", localDir.filePath(QStringLiteral("symlink")).toUtf8().data()), 0);

	QVERIFY(forceNodeTimeout());

	QCOMPARE(QFile::symLinkTarget(mirrorDir.filePath(QStringLiteral("symlink"))), QStringLiteral("/newtarget"));
}

void FileOpsTest::testTypeRefresh()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localDir.path())).value();
	QVERIFY(!reply.isEmpty());

	QDir mirrorDir(reply);
	QVERIFY(mirrorDir.exists());

	// Create a file and directory
	QFile localFile(localDir.filePath(QStringLiteral("changingtodir")));
	QVERIFY(localFile.open(QFile::ReadWrite));
	QVERIFY(QDir(localDir.path()).mkdir(QStringLiteral("changingtofile")));

	// Open it on the mirror
	QFile changingMirrorFile(mirrorDir.filePath(QStringLiteral("changingtodir")));
	QVERIFY(changingMirrorFile.open(QFile::ReadOnly));

	// Replace the file locally  with a directory
	QVERIFY(localFile.remove());
	QVERIFY(QDir(localDir.path()).mkdir(QStringLiteral("changingtodir")));

	QVERIFY(forceNodeTimeout());

	// Verify that it's a directory now
	struct stat st;
	QCOMPARE(stat(qPrintable(changingMirrorFile.fileName()), &st), 0);
	QCOMPARE(st.st_mode & S_IFMT, S_IFDIR);

	// The opened file still refers to the (now deleted) file
	QCOMPARE(fstat(changingMirrorFile.handle(), &st), 0);
	QCOMPARE(st.st_mode & S_IFMT, S_IFREG);
}

#ifdef WASTE_DISK_SPACE
void FileOpsTest::testReadWrite4GBFile()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());

	// Mount the temporary file
	QString reply = m_kiofuse_iface.mountUrl(QStringLiteral("file://%1").arg(localFile.fileName())).value();
	QVERIFY(!reply.isEmpty());

	QFile mirroredFile(reply);
	QVERIFY(mirroredFile.exists());
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));

	// Write new data at a 2^32 offset
	QVERIFY(mirroredFile.seek(qint64(4096)*1024*1024));
	QCOMPARE(mirroredFile.write(QStringLiteral("newteststring!").toUtf8()), 14);

	QVERIFY(mirroredFile.flush());
	// Flush the written contents into the backend
	QCOMPARE(fsync(mirroredFile.handle()), 0);

	// Currently, kio-fuse uses KIO::put and not KIO::write, so the file was replaced
	// instead of changed. So reopen the file.
	QFile localFile2(localFile.fileName());
	QVERIFY(localFile2.open(QIODevice::ReadOnly));;

	// Compare the content
	QVERIFY(localFile2.seek(qint64(4096)*1024*1024-6));
	QCOMPARE(localFile2.read(20), QByteArray("\x00\x00\x00\x00\x00\x00newteststring!", 20));
	QVERIFY(localFile2.seek(qint64(4096)*4096*1024-6));
	QCOMPARE(localFile2.read(20), QByteArray());
	QVERIFY(localFile2.seek(qint64(4096)*1024*1024-6));
	QVERIFY(mirroredFile.seek(qint64(4096)*1024*1024-6));
	QCOMPARE(localFile2.read(20), mirroredFile.read(20));
}
#endif // WASTE_DISK_SPACE

QDateTime FileOpsTest::roundDownToSecond(QDateTime dt)
{
	return QDateTime::fromTime_t(dt.toTime_t());
}

bool FileOpsTest::forceNodeTimeout()
{
	auto reply = m_kiofuseprivate_iface.forceNodeTimeout();
	reply.waitForFinished();
	return !reply.isError();
}

QTEST_GUILESS_MAIN(FileOpsTest)

#include "fileopstest.moc"
