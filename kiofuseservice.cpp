/*
 * Copyright 2019 Alexander Saoutkin <a.saoutkin@gmail.com>
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

#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include <QDBusConnection>
#include <QStandardPaths>
#include <QDir>

#include "debug.h"
#include "kiofuseservice.h"
#include "kiofusevfs.h"

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

QString KIOFuseService::mountUrl(const QString& remoteUrl, const QDBusMessage& message)
{
	message.setDelayedReply(true);
	QUrl url = QUrl::fromUserInput(remoteUrl);
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
	return QDBusConnection::sessionBus().registerObject(QStringLiteral("/org/kde/KIOFuse"), this, QDBusConnection::ExportAllSlots)
	    && QDBusConnection::sessionBus().registerService(QStringLiteral("org.kde.KIOFuse"));
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