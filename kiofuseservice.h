/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include <optional>

#include <QObject>
#include <QDBusMessage>
#include <QDBusContext>
#include <QTemporaryDir>
#include <QStandardPaths>
#include <QDBusAbstractAdaptor>

#include "kiofusevfs.h"

class KIOFuseServicePrivate : public QDBusAbstractAdaptor {
	Q_OBJECT
	Q_CLASSINFO("D-Bus Interface", "org.kde.KIOFuse.Private")

public:
	KIOFuseServicePrivate(QObject *obj) : QDBusAbstractAdaptor(obj) {}

public Q_SLOTS:
	/** Treat all nodes as expired, to not have to wait in automated testing. */
	void forceNodeTimeout();
};

class KIOFuseService : public QObject, protected QDBusContext
{
	Q_OBJECT
	Q_CLASSINFO("D-Bus Interface", "org.kde.KIOFuse.VFS")

public:
	virtual ~KIOFuseService();
	/** Attempts to register the service and start kiofusevfs. If both succeed,
	  * returns true, false otherwise. */
	bool start(struct fuse_args &args, QString mountpoint, bool foreground);
	KIOFuseVFS kiofusevfs;

public Q_SLOTS:
	/** Mounts a URL onto the filesystem, and returns the local path back. */
	QString mountUrl(const QString &remoteUrl, const QDBusMessage &message);
	/** Converts a local path into a remote URL if it is mounted within the VFS */
	QString remoteUrl(const QString &localPath);

private Q_SLOTS:
	/** Stops the VFS when the DBus connection is lost. */
	void dbusDisconnected();

private:
	/** Registers the kio-fuse process as the org.kde.KIOFuse service.
	  * Returns false if this fails (otherwise you can't communicate with the process), true otherwise.*/
	bool registerService();
	/** Daemonizes the kio-fuse process, whilst also managing the registration of the org.kde.KIOFuse service.
	  * Derived from fuse_daemonize() in libfuse. */
	bool registerServiceDaemonized();
	/** where kiofusevfs is mounted */
	QString m_mountpoint;
	/** tempdir created if user does not specify mountpoint */
	std::optional<QTemporaryDir> m_tempDir;
	/** A list of protocols that are blacklisted (for various reasons). */
	static const QStringList m_blacklist;
	/** DBus Adaptor exported as org.kde.KIOFuse.Private interface. */
	KIOFuseServicePrivate m_privateInterface{this};
};
