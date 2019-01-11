#include "kiofusenode.h"

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
			path.prepend({}); // Add a leading slash if necessary
			QUrl url = dynamic_cast<const KIOFuseOriginNode*>(currentNode)->m_baseUrl;
			url.setPath(url.path() + path.join(QLatin1Char('/')), QUrl::DecodedMode);
			return url;
		}

		path.prepend(currentNode->m_nodeName);
	}

	// No OriginNode found until the root - return an invalid URL
	return {};
}

QUrl KIOFuseRemoteFileNode::remoteUrl(std::function<KIOFuseNode*(fuse_ino_t)> nodeAccessor) const
{
	if(!m_overrideUrl.isEmpty())
		return m_overrideUrl;

	return KIOFuseNode::remoteUrl(nodeAccessor);
}
