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

	// Typesafe cast based on type
	template<class T> T *as()
	{
		if(type() == T::Type)
			return static_cast<T*>(this);

		return nullptr;
	}

	// Typesafe cast based on type
	template<class T> const T *as() const
	{
		if(type() == T::Type)
			return static_cast<const T*>(this);

		return nullptr;
	}

	// Returns the path upwards until a root node.
	QString virtualPath(std::function<KIOFuseNode*(fuse_ino_t)> nodeAccessor) const;
	// Returns the url upwards until a OriginNode is hit.
	// If no OriginNode is found, an empty QUrl is returned
	QUrl remoteUrl(std::function<KIOFuseNode*(fuse_ino_t)> nodeAccessor) const;

	uint64_t m_lookupCount = 0;
	fuse_ino_t m_parentIno;
	QString m_nodeName;
	// TODO: nlink of directories (./..)?
	struct stat m_stat;
};

class KIOFuseDirNode : public KIOFuseNode {
public:
	using KIOFuseNode::KIOFuseNode;
	std::vector<fuse_ino_t> m_childrenInos;
};

template<> KIOFuseDirNode *KIOFuseNode::as();
template<> const KIOFuseDirNode *KIOFuseNode::as() const;

class KIOFuseRootNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::RootNode;
	NodeType type() const override { return Type; }
};

class KIOFuseDeletedRootNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::DeletedRootNode;
	NodeType type() const override { return Type; }
};

class KIOFuseProtocolNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::ProtocolNode;
	NodeType type() const override { return Type; }
};

class KIOFuseOriginNode : public KIOFuseDirNode {
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::OriginNode;
	NodeType type() const override { return Type; }
	QUrl m_baseUrl;
};

class KIOFuseRemoteDirNode : public QObject, public KIOFuseDirNode {
	Q_OBJECT
public:
	using KIOFuseDirNode::KIOFuseDirNode;
	static const NodeType Type = NodeType::RemoteDirNode;
	NodeType type() const override { return Type; }

	bool m_childrenComplete = false, m_childrenRequested = false;

Q_SIGNALS:
	void gotChildren(bool success);
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
	FILE *m_localCache = nullptr; // The tmpfile containing data. If nullptr, not requested yet.
	size_t m_cacheSize = 0;
	bool m_cacheComplete = false, m_cacheDirty = false;

Q_SIGNALS:
	void localCacheChanged(int error);
};

class KIOFuseSymLinkNode : public QObject, public KIOFuseNode {
	Q_OBJECT
public:
	using KIOFuseNode::KIOFuseNode;
	static const NodeType Type = NodeType::RemoteSymlinkNode;
	NodeType type() const override { return Type; }
	QString m_target;

Q_SIGNALS:
	void gotSymlinkTarget(QString &target);
};
