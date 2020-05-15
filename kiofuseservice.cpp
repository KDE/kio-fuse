/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include <QDBusConnection>
#include <QStandardPaths>
#include <QDir>

#include "debug.h"
#include "kiofuseservice.h"
#include "kiofusevfs.h"

const QStringList KIOFuseService::m_blacklist {
    QStringLiteral("gdrive"), // @see #1
    QStringLiteral("mtp"), // @see #2
    // http(s) is buggy and gives back invalid sizes (similar to gdrive).
    QStringLiteral("https"),
    QStringLiteral("http")
};

KIOFuseService::~KIOFuseService()
{
	// Make sure the VFS is unmounted before the member destructors run.
	// Any access to the mountpoint would deadlock.
	kiofusevfs.stop();
}

bool KIOFuseService::start(struct fuse_args &args, QString mountpoint, bool foreground)
{
	if(!m_mountpoint.isEmpty())
	{
		qWarning(KIOFUSE_LOG) << "Refusing to start already running KIOFuseService";
		return false;
	}

	if(mountpoint.isEmpty())
	{
		const QString runtimeloc = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
		if(runtimeloc.isEmpty())
			return false;

		m_tempDir.emplace(runtimeloc + QStringLiteral("/kio-fuse-XXXXXX"));
		if(!m_tempDir.value().isValid())
			return false; // Abort if can't mkdir for some reason

		m_mountpoint = m_tempDir.value().path();
	}
	else
		// Don't do a mkdir here, we assume that any given mountpoint dir already exists.
		m_mountpoint = mountpoint;

	if(!kiofusevfs.start(args, m_mountpoint))
		return false;

	if(foreground)
		return registerService();
	else
		return registerServiceDaemonized();
}

void KIOFuseServicePrivate::forceNodeTimeout()
{
	g_timeoutEpoch = std::chrono::steady_clock::now();
}

QString KIOFuseService::remoteUrl(const QString& localPath)
{
	// Massage URL into something KIOFuseVFS may understand.
	QDir mountpoint(m_mountpoint);
	QString relativePath = mountpoint.relativeFilePath(localPath);
	// If relativePath is empty or starts with ../, this would get error out
	QUrl remoteUrl = kiofusevfs.localPathToRemoteUrl(relativePath);

	if(remoteUrl.isEmpty())
	{
		sendErrorReply(
			QStringLiteral("org.kde.KIOFuse.VFS.Error.RemoteURLNotFound"),
			QStringLiteral("The given path does not have a remote URL equivalent: %1").arg(localPath)
		);
		return QString();
	}

	return remoteUrl.toString(QUrl::RemovePassword);
}

void KIOFuseService::dbusDisconnected()
{
	qInfo(KIOFUSE_LOG) << "DBus disconnected - stopping.";
	kiofusevfs.stop();
}

QString KIOFuseService::mountUrl(const QString& remoteUrl, const QDBusMessage& message)
{
	message.setDelayedReply(true);
	QUrl url = QUrl::fromUserInput(remoteUrl);
	if(m_blacklist.contains(url.scheme()))
	{
		url.setPassword({}); // Lets not give back passwords in plaintext...
		auto errorReply = message.createErrorReply(
			QStringLiteral("org.kde.KIOFuse.VFS.Error.SchemeNotSupported"),
			QStringLiteral("KIOFuse does not suport mounting of URLs with a scheme of %1").arg(url.scheme())
		);
		QDBusConnection::sessionBus().send(errorReply);
		return QString();
	}
	kiofusevfs.mountUrl(url, [=] (auto node, int error) {
		if(error)
		{
			QUrl displayUrl = url;
			displayUrl.setPassword({}); // Lets not give back passwords in plaintext...
			auto errorReply = message.createErrorReply(
				QStringLiteral("org.kde.KIOFuse.VFS.Error.CannotMount"),
				QStringLiteral("KIOFuse failed to mount %1: %2").arg(displayUrl.toString(), QLatin1String(strerror(error)))
			);
			QDBusConnection::sessionBus().send(errorReply);
			return;
		}

		QString localPath = {m_mountpoint + kiofusevfs.virtualPath(node)};
		QDBusConnection::sessionBus().send(message.createReply() << localPath);
	});
	return QString();
}

bool KIOFuseService::registerService()
{
	if(QDBusConnection::sessionBus().registerObject(QStringLiteral("/org/kde/KIOFuse"), this,
	                                                    QDBusConnection::ExportAllSlots | QDBusConnection::ExportAdaptors)
	    && QDBusConnection::sessionBus().registerService(QStringLiteral("org.kde.KIOFuse")))
	{
		QDBusConnection::sessionBus().connect({}, QStringLiteral("/org/freedesktop/DBus/Local"), QStringLiteral("org.freedesktop.DBus.Local"), QStringLiteral("Disconnected"), this, SLOT(dbusDisconnected()));
		return true;
	}

	return false;
}

bool KIOFuseService::registerServiceDaemonized()
{
	int waiter[2];
	int result = 1;

	if(pipe(waiter)) {
		perror("kiofuse_daemonize: pipe");
		return false;
	}

	/*
	* demonize current process by forking it and killing the
	* parent.  This makes current process as a child of 'init'.
	*/
	pid_t cpid = fork();
	switch(cpid) {
	case -1: // fork failed
		perror("kiofuse_daemonize: fork");
		return false;
	default: // Parent
		(void) read(waiter[0], &result, sizeof(result));
		if(result)
			waitpid(cpid, nullptr, 0);
		_exit(result);
	case 0: // Child
		break;
	}

	result = registerService() ? 0 : 1;

	if(setsid() == -1) {
		perror("kiofuse_daemonize: setsid");
		result = 1;
	}

	(void) chdir("/");

	/* Propagate completion of daemon initialization */
	(void) write(waiter[1], &result, sizeof(result));
	close(waiter[0]);
	close(waiter[1]);

	return result == 0;
}
