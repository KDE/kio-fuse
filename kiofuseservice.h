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

#pragma once

#include <optional>

#include <QObject>
#include <QDBusMessage>
#include <QTemporaryDir>
#include <QStandardPaths>

#include "kiofusevfs.h"

class KIOFuseService : public QObject
{
	Q_OBJECT
	Q_CLASSINFO("D-Bus Interface", "org.kde.KIOFuse.VFS")

public:
	virtual ~KIOFuseService();
	/** Attempts to register the service and start kiofusevfs. If both succeed,
	  * returns true, false otherwise. */
	bool start(struct fuse_args &args, QString mountpoint, bool foreground);

public Q_SLOTS:
	/** Mounts a URL onto the filesystem, and returns the local path back. */
	QString mountUrl(const QString &remoteUrl, const QDBusMessage &message);

private:
	/** Registers the kio-fuse process as the org.kde.KIOFuse service.
	  * Returns false if this fails (otherwise you can't communicate with the process), true otherwise.*/
	bool registerService();
	/** Daemonizes the kio-fuse process, whilst also managing the registration of the org.kde.KIOFuse service.
	  * Derived from fuse_daemonize() in libfuse. */
	bool registerServiceDaemonized();
	KIOFuseVFS kiofusevfs;
	/** where kiofusevfs is mounted */
	QString m_mountpoint;
	/** tempdir created if user does not specify mountpoint */
	std::optional<QTemporaryDir> m_tempDir;

};
