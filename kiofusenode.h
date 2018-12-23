#pragma once

#include <fuse_lowlevel.h>

#include <vector>

#include <QObject>
#include <QUrl>
#include <QString>

class KIOFuseNode {
public:
	KIOFuseNode(const fuse_ino_t parentIno, QString nodeName) :
	    m_parentIno(parentIno),
	    m_nodeName(nodeName)
	{}

	virtual ~KIOFuseNode() {}

	enum class NodeType {
		// Dir types
		RootNode,
		DeletedRootNode,
		ProtocolNode,
		OriginNode,
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

	uint64_t m_lookupCount = 0;
	fuse_ino_t m_parentIno;
	// TODO: nlink of directories (./..)?
	struct stat m_stat;
	QString m_nodeName;
};

class KIOFuseDirNode : public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	std::vector<fuse_ino_t> m_childrenInos;
};

class KIOFuseRootNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	NodeType type() const override { return NodeType::RootNode; }
};

class KIOFuseDeletedRootNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	NodeType type() const override { return NodeType::DeletedRootNode; }
};

class KIOFuseProtocolNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	NodeType type() const override { return NodeType::ProtocolNode; }
};

class KIOFuseOriginNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	NodeType type() const override { return NodeType::OriginNode; }
	QUrl m_baseUrl;
};

class KIOFuseRemoteDirNode : public QObject, KIOFuseDirNode {
	Q_OBJECT
public:
	NodeType type() const override { return NodeType::RemoteDirNode; }

	bool m_childrenComplete = false, m_childrenRequested = false;

signals:
	void gotChildren(bool success);
};

class KIOFuseControlNode : public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	NodeType type() const override { return NodeType::ControlNode; }
};

class KIOFuseRemoteFileNode : public QObject, KIOFuseNode {
	Q_OBJECT
public:
	NodeType type() const override { return NodeType::RemoteFileNode; }
	// Cache information
	int m_localCacheFD = -1;
	bool m_cacheValid = false, m_cacheRequested = false, m_cacheDirty = false;

signals:
	void localCacheChanged(size_t size);
};

class KIOFuseSymLinkNode : public QObject, KIOFuseNode {
	Q_OBJECT
public:
	NodeType type() const override { return NodeType::RemoteSymlinkNode; }
	QString m_target;

signals:
	void gotSymlinkTarget(QString &target);
};
