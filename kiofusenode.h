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

#pragma once

#include <fuse_lowlevel.h>

#include <functional>
#include <vector>

#include <QObject>
#include <QUrl>
#include <QString>

class KIOFuseNode {
public:
	// Creates a new node. Make sure to set the node's m_stat.st_ino once inserted.
	KIOFuseNode(const fuse_ino_t parentIno, QString nodeName, const struct stat &stat) :
	    m_parentIno(parentIno),
	    m_nodeName(nodeName),
	    m_stat(stat)
	{}

	virtual ~KIOFuseNode() {}

	enum class NodeType {
		// Dir types
		RootNode,
		ProtocolNode,
		RemoteDirNode,
		LastDirType = RemoteDirNode,

		// File types
		ControlNode,
		RemoteFileNode,
		RemoteSymlinkNode,
	};

	// By having this as a virtual method instead of a class member
	// this is "for free" - the vtable ptr is enough
	virtual NodeType type() const = 0;

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

class KIOFuseRootNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::RootNode;
	NodeType type() const override { return Type; }
};

class KIOFuseProtocolNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::ProtocolNode;
	NodeType type() const override { return Type; }
};

class KIOFuseRemoteDirNode : public QObject, public KIOFuseDirNode {
	Q_OBJECT
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::RemoteDirNode;
	NodeType type() const override { return Type; }

	// Override the URL
	QUrl m_overrideUrl;

	// Whether the list of children is the result of a successful dirlist
	bool m_childrenComplete = false;
	// Whether a dirlist was requested. If true, the signal "gotChildren" will
	// be emitted on finish.
	bool m_childrenRequested = false;

Q_SIGNALS:
	// Emitted after finishing (successful or not) a distlist on this node
	void gotChildren(int error);
};

class KIOFuseControlNode : public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	static const NodeType Type = NodeType::ControlNode;
	NodeType type() const override { return Type; }
};

class KIOFuseRemoteFileNode : public QObject, public KIOFuseNode {
	Q_OBJECT
public:
	using KIOFuseNode::KIOFuseNode;
	~KIOFuseRemoteFileNode() {
		if(m_localCache)
			fclose(m_localCache);
	}
	static const NodeType Type = NodeType::RemoteFileNode;
	NodeType type() const override { return Type; }
	// Cache information
	bool cacheIsComplete() { return m_cacheComplete; }
	FILE *m_localCache = nullptr; // The tmpfile containing data. If nullptr, not requested yet.
	size_t m_cacheSize = 0; // Size of the local cache - might be less than m_stat.st_size.
	int m_cacheComplete = false,
	    m_cacheDirty = false, // Set on every write to m_localCache, cleared when a flush starts
	    m_flushRunning = false; // If a flush is currently running

	// Override the URL (used for UDS_URL)
	QUrl m_overrideUrl;
Q_SIGNALS:
	// Emitted when a download operation on this node made progress, finished or failed.
	void localCacheChanged(int error);
	// Emitted after finishing (successful or not) a cache flush on this node
	void cacheFlushed(int error);
};

class KIOFuseSymLinkNode : public QObject, public KIOFuseNode {
	Q_OBJECT
public:
	using KIOFuseNode::KIOFuseNode;
	static const NodeType Type = NodeType::RemoteSymlinkNode;
	NodeType type() const override { return Type; }
	QString m_target;
};
