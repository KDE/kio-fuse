#include "kiofusenode.h"

template<> KIOFuseDirNode *KIOFuseNode::as()
{
	if(type() <= NodeType::LastDirType)
		return static_cast<KIOFuseDirNode*>(this);

	return nullptr;
}

template<> const KIOFuseDirNode *KIOFuseNode::as() const
{
	if(type() <= NodeType::LastDirType)
		return static_cast<const KIOFuseDirNode*>(this);

	return nullptr;
}

QString KIOFuseNode::virtualPath(std::function<KIOFuseNode*(fuse_ino_t)> nodeAccessor) const
{
	QStringList path;
	for(const KIOFuseNode *currentNode = this; currentNode != nullptr; currentNode = nodeAccessor(currentNode->m_parentIno))
		path.prepend(currentNode->m_nodeName);

	return path.join(QLatin1Char('/'));
}

QUrl KIOFuseNode::remoteUrl(std::function<KIOFuseNode *(fuse_ino_t)> nodeAccessor) const
{
	QStringList path;
	for(const KIOFuseNode *currentNode = this; currentNode != nullptr; currentNode = nodeAccessor(currentNode->m_parentIno))
	{
		if(currentNode->type() == NodeType::OriginNode)
		{
			// Origin node found - add path and return

			// Add the leading slash
			path.prepend({});

			QUrl url = currentNode->as<KIOFuseOriginNode>()->m_baseUrl;
			url.setPath(path.join(QLatin1Char('/')), QUrl::DecodedMode);
			return url;
		}

		path.prepend(currentNode->m_nodeName);
	}

	// No OriginNode found until the root - return an invalid URL
	return {};
}
