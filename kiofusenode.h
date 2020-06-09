/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include <fuse_lowlevel.h>

#include <functional>
#include <vector>
#include <chrono>

#include <QObject>
#include <QUrl>
#include <QString>

#include <KIO/FileJob>

class KIOFuseNode {
public:
	// Creates a new node. Make sure to set the node's m_stat.st_ino once inserted.
	KIOFuseNode(const fuse_ino_t parentIno, QString nodeName, const struct stat &stat) :
	    m_parentIno(parentIno),
	    m_nodeName(nodeName),
	    m_stat(stat)
	{}

	virtual ~KIOFuseNode() {}

	uint64_t m_lookupCount = 0, // This counts how many references to this node the kernel has
	         m_openCount = 0; // This counts how often the kernel has this node opened
	fuse_ino_t m_parentIno;
	QString m_nodeName;
	// TODO: nlink of directories (./..)?
	struct stat m_stat;
};

// Base class for all nodes representing a directory
class KIOFuseDirNode : public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	std::vector<fuse_ino_t> m_childrenInos;
};

// Used for automated testing of expiration.
// Set by KIOFuseServicePrivate::forceNodeTimeout.
extern std::chrono::steady_clock::time_point g_timeoutEpoch;

class KIOFuseRemoteNodeInfo : public QObject {
	Q_OBJECT
public:
	// Timeout for refreshing of attributes
	static const std::chrono::steady_clock::duration ATTR_TIMEOUT;
	// Override the URL
	QUrl m_overrideUrl;
	// Whether a stat was requested. If true, the signal "statRefreshed" will
	// be emitted on finish.
	bool m_statRequested = false;
	// Stores the last time a node's m_stat field was refreshed via KIO::stat or a parent's KIO::listDir.
	std::chrono::steady_clock::time_point m_lastStatRefresh = std::chrono::steady_clock::now();
	// Returns true if a node is due for a stat refresh, false otherwise.
	bool hasStatTimedOut() { return m_lastStatRefresh < g_timeoutEpoch || (std::chrono::steady_clock::now() - m_lastStatRefresh) >= ATTR_TIMEOUT; }
Q_SIGNALS:
	// Emitted after finishing (successful or not) a attr refresh on this node
	void statRefreshed(int error);
};

class KIOFuseRemoteDirNode : public KIOFuseRemoteNodeInfo, public KIOFuseDirNode {
	Q_OBJECT
public:
	using KIOFuseDirNode::KIOFuseDirNode;

	// Whether a dirlist was requested. If true, the signal "gotChildren" will
	// be emitted on finish.
	bool m_childrenRequested = false;
	// Stores the last time a node's children were refreshed via KIO::listDir.
	std::chrono::steady_clock::time_point m_lastChildrenRefresh;
	// Returns true if a node is due for a readdir refresh, false otherwise.
	bool haveChildrenTimedOut() { return m_lastChildrenRefresh < g_timeoutEpoch || (std::chrono::steady_clock::now() - m_lastChildrenRefresh) >= ATTR_TIMEOUT; }

Q_SIGNALS:
	// Emitted after finishing (successful or not) a distlist on this node
	void gotChildren(int error);
};

class KIOFuseRemoteFileNode : public KIOFuseRemoteNodeInfo, public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
};

class KIOFuseRemoteCacheBasedFileNode : public KIOFuseRemoteFileNode {
	Q_OBJECT
public:
	using KIOFuseRemoteFileNode::KIOFuseRemoteFileNode;
	~KIOFuseRemoteCacheBasedFileNode() {
		if(m_localCache)
			fclose(m_localCache);
	}
	// Cache information
	bool cacheIsComplete() { return m_cacheComplete; }
	FILE *m_localCache = nullptr; // The tmpfile containing data. If nullptr, not requested yet.
	off_t m_cacheSize = 0; // Size of the local cache - might be less than m_stat.st_size.
	bool m_cacheComplete = false,
	     m_cacheDirty = false, // Set on every write to m_localCache, cleared when a flush starts
	     m_flushRunning = false; // If a flush is currently running
	int m_numKilledJobs = 0; // reset on successful flush, incremented every time job is killed because cache is dirty (among other factors)
Q_SIGNALS:
	// Emitted when a download operation on this node made progress, finished or failed.
	void localCacheChanged(int error);
	// Emitted after finishing (successful or not) a cache flush on this node
	void cacheFlushed(int error);
};

class KIOFuseRemoteFileJobBasedFileNode : public KIOFuseRemoteFileNode {
public:
	using KIOFuseRemoteFileNode::KIOFuseRemoteFileNode;
};

class KIOFuseSymLinkNode : public KIOFuseRemoteNodeInfo, public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	QString m_target;
};
