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

class FileOpsTest : public QObject
{
	Q_OBJECT

private Q_SLOTS:
	void initTestCase();
	void cleanupTestCase();

	void testControlFile();
	void testLocalFileOps();
	void testLocalDirOps();
	void testCreationOps();
	void testRenameOps();
	void testDeletionOps();
	void testArchiveOps();
	void testKioErrorMapping();
#ifdef WASTE_DISK_SPACE
	void testReadWrite4GBFile();
#endif // WASTE_DISK_SPACE

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

	// Make sure that it works with both truncation and without
	QVERIFY(m_controlFile.open(QIODevice::WriteOnly | QIODevice::Unbuffered));
	m_controlFile.close();
	QVERIFY(m_controlFile.open(QIODevice::WriteOnly | QIODevice::Unbuffered | QIODevice::Truncate));
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

	QFile mirroredFile(QStringLiteral("%1/file%2").arg(m_mountDir.path(), localFile.fileName()));
	QVERIFY(mirroredFile.exists());
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
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
	QVERIFY(stat(localFile.fileName().toUtf8().data(), &attr) == 0);
	QCOMPARE(attr.st_mode, S_IFREG | 0054);
	QCOMPARE(chmod(mirroredFile.fileName().toUtf8().data(), 0600), 0);
	QVERIFY(stat(localFile.fileName().toUtf8().data(), &attr) == 0);
	QCOMPARE(attr.st_mode, S_IFREG | 0600);

	// Mount the data path
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	cmd = QStringLiteral("MOUNT file://%1").arg(dataPath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());
	QString mirrordataPath = QStringLiteral("%1/file%2").arg(m_mountDir.path(), dataPath);

	// Verify the symlink inside is correct
	QFile symlink(QDir(mirrordataPath).filePath(QStringLiteral("symlink")));

	QVERIFY(symlink.open(QIODevice::ReadOnly));
	QCOMPARE(symlink.readAll(), QStringLiteral("symlinktargetcontent").toUtf8());
	QCOMPARE(symlink.symLinkTarget(), QDir(mirrordataPath).filePath(QStringLiteral("symlinktarget")));
}

void FileOpsTest::testLocalDirOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localDir.path()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QDir mirrorDir(QStringLiteral("%1/file/%2").arg(m_mountDir.path(), localDir.path()));
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
	QVERIFY(stat(localDir.path().toUtf8().data(), &attr) == 0);
	QCOMPARE(attr.st_mode, S_IFDIR | 0054);
	QCOMPARE(chmod(mirrorDir.path().toUtf8().data(), 0700), 0);
	QVERIFY(stat(localDir.path().toUtf8().data(), &attr) == 0);
	QCOMPARE(attr.st_mode, S_IFDIR | 0700);

	// Mount the data path and compare the directory content
	QString dataPath = QFINDTESTDATA(QStringLiteral("data"));
	QVERIFY(!dataPath.isEmpty());
	cmd = QStringLiteral("MOUNT file://%1").arg(dataPath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());
	QString mirrordataPath = QStringLiteral("%1/file%2").arg(m_mountDir.path(), dataPath);

	auto sourceEntryList = QDir(dataPath).entryList(QDir::NoFilter, QDir::Name);
	auto mirrorEntryList = QDir(mirrordataPath).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);

	// Make sure dirlisting file:/// works
	sourceEntryList = QDir(QStringLiteral("/")).entryList(QDir::NoFilter, QDir::Name);
	mirrorEntryList = QDir(QStringLiteral("%1/file").arg(m_mountDir.path())).entryList(QDir::NoFilter, QDir::Name);

	QCOMPARE(mirrorEntryList, sourceEntryList);
}

void FileOpsTest::testCreationOps()
{
	QTemporaryDir localDir;
	QVERIFY(localDir.isValid());

	// Mount the temporary dir
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localDir.path()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QDir mirrorDir(QStringLiteral("%1/file/%2").arg(m_mountDir.path(), localDir.path()));
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
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localDir.path()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QDir mirrorDir(QStringLiteral("%1/file/%2").arg(m_mountDir.path(), localDir.path()));
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
	QCOMPARE(rename(mirrorDir.filePath(QStringLiteral("dirb/fileb")).toUtf8().data(),
	                mirrorDir.filePath(QStringLiteral("dirb/filec")).toUtf8().data()), 0);

	QVERIFY(!QFile::exists(localDir.filePath(QStringLiteral("dirb/fileb"))));
	QVERIFY(QFile::exists(localDir.filePath(QStringLiteral("dirb/filec"))));
	QVERIFY(!QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/fileb"))));
	QVERIFY(QFile::exists(mirrorDir.filePath(QStringLiteral("dirb/filec"))));

	// Both handles must still be valid
	QVERIFY(overwrittenFile.seek(0));
	QCOMPARE(overwrittenFile.readAll(), QStringLiteral("data").toUtf8());

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
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localDir.path()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QDir mirrorDir(QStringLiteral("%1/file/%2").arg(m_mountDir.path(), localDir.path()));
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
	QCOMPARE(errno, EISDIR);
	QCOMPARE(rmdir(dir.path().toUtf8().data()), -1);
	QCOMPARE(errno, ENOTEMPTY);

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

	// Not implemented: Link the file back into the tree, if possible
	// QCOMPARE(link(QStringLiteral("/proc/self/fd/%1").arg(file.handle()).toUtf8().data(),
	//              mirrorDir.filePath(QStringLiteral("deletedFile")).toUtf8().data()), 0);
	// ... test that the file is still open and connected.
}

void FileOpsTest::testArchiveOps()
{
	QString outerpath = QFINDTESTDATA(QStringLiteral("data/outerarchive.tar.gz"));

	// Mount a file inside the archive
	QByteArray cmd = QStringLiteral("MOUNT tar://%1/outerarchive/outerfile").arg(outerpath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	// And verify its content
	QString outerfilepath = QStringLiteral("%1/tar%2/outerarchive/outerfile").arg(m_mountDir.path(), outerpath);
	QFile outerfile(outerfilepath);
	QVERIFY(outerfile.open(QIODevice::ReadOnly));
	QCOMPARE(outerfile.readAll(), QStringLiteral("outercontent").toUtf8());

	QString innerpath = QStringLiteral("%1/tar%2/outerarchive/innerarchive.tar.gz").arg(m_mountDir.path(), outerpath);

	// Unfortunately kio_archive is not reentrant, so a direct access would deadlock.
	// As a workaround, cache the file to avoid a 2nd call into kio_archive.
	QFile innerarchiveFile(innerpath);
	QVERIFY(innerarchiveFile.open(QIODevice::ReadOnly));
	QVERIFY(!innerarchiveFile.readAll().isEmpty());

	// Next, mount an archive inside - this uses kio-fuse recursively
	cmd = QStringLiteral("MOUNT tar://%1").arg(innerpath).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QFile innerfile(QStringLiteral("%1/tar%2/innerarchive/innerfile").arg(m_mountDir.path(), innerpath));
	QVERIFY(innerfile.open(QIODevice::ReadOnly));
	QCOMPARE(innerfile.readAll(), QStringLiteral("innercontent").toUtf8());
}

void FileOpsTest::testKioErrorMapping()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());
	
	// Mount the temporary file
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localFile.fileName()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());
	
	QFile mirroredFile(QStringLiteral("%1/file%2").arg(m_mountDir.path(), localFile.fileName()));
	QVERIFY(mirroredFile.exists());
	QVERIFY(mirroredFile.open(QIODevice::ReadWrite));
	QCOMPARE(mirroredFile.size(), localFile.size());
	// No permission to chown to root/root (unless running with CAP_CHOWN or being root)
	QCOMPARE(chown(mirroredFile.fileName().toUtf8().data(), 0, 0), -1);
	QCOMPARE(errno, EPERM);
}


#ifdef WASTE_DISK_SPACE
void FileOpsTest::testReadWrite4GBFile()
{
	QTemporaryFile localFile;
	QVERIFY(localFile.open());

	// Mount the temporary file
	QByteArray cmd = QStringLiteral("MOUNT file://%1").arg(localFile.fileName()).toUtf8();
	QCOMPARE(m_controlFile.write(cmd), cmd.length());

	QFile mirroredFile(QStringLiteral("%1/file%2").arg(m_mountDir.path(), localFile.fileName()));
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

QTEST_GUILESS_MAIN(FileOpsTest)

#include "fileopstest.moc"
