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
