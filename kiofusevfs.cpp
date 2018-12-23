#include <unistd.h>
#include <sys/types.h>

#include <QDebug>

#include "kiofusevfs.h"

const struct fuse_lowlevel_ops KIOFuseVFS::fuse_ll_ops = {
	.lookup = &KIOFuseVFS::lookup,
	.forget = &KIOFuseVFS::forget,
	.getattr = &KIOFuseVFS::getattr,
	.readdir = &KIOFuseVFS::readdir,
};

KIOFuseVFS::KIOFuseVFS(QObject *parent)
    : QObject(parent)
{
	struct stat attr = {};
	attr.st_nlink = 1;
	attr.st_mode = S_IFDIR | 0755;
	attr.st_uid = getuid();
	attr.st_gid = getgid();
	attr.st_size = 1;
	attr.st_blksize = 4096;
	attr.st_blocks = 1;

	// TODO: Add insert function?
	auto root = std::make_unique<KIOFuseRootNode>(KIOFuseIno::Invalid, QString());
	attr.st_ino = KIOFuseIno::Root;
	root->m_stat = attr;

	auto control = std::make_unique<KIOFuseControlNode>(KIOFuseIno::Root, QStringLiteral("_control"));
	attr.st_ino = KIOFuseIno::Control;
	attr.st_mode = S_IFREG | 0700;
	control->m_stat = attr;

	m_nodes[KIOFuseIno::Control] = std::move(control);
	root->m_childrenInos.push_back(KIOFuseIno::Control);

	m_nodes[KIOFuseIno::Root] = std::move(root);
}

KIOFuseVFS::~KIOFuseVFS()
{
	stop();
}

bool KIOFuseVFS::start(struct fuse_args &args, const char *mountpoint)
{
	stop();

	m_fuseSession = fuse_session_new(&args, &fuse_ll_ops, sizeof(fuse_ll_ops), this);

	if(!m_fuseSession)
		return false;

	if(fuse_set_signal_handlers(m_fuseSession) != 0
	   || fuse_session_mount(m_fuseSession, mountpoint) != 0)
	{
		stop();
		return false;
	}

	m_fuseNotifier = new QSocketNotifier(fuse_session_fd(m_fuseSession), QSocketNotifier::Read, this);
	m_fuseNotifier->connect(m_fuseNotifier, &QSocketNotifier::activated, this, &KIOFuseVFS::fuseRequestPending);

	return true;
}

void KIOFuseVFS::stop()
{
	if(m_fuseSession)
	{
		fuse_remove_signal_handlers(m_fuseSession);
		fuse_session_unmount(m_fuseSession);
		fuse_session_destroy(m_fuseSession);
		m_fuseSession = nullptr;
	}

	if(m_fuseNotifier)
	{
		delete m_fuseNotifier;
		m_fuseNotifier = nullptr;
	}
}

#include <QCoreApplication>
void KIOFuseVFS::fuseRequestPending()
{
	struct fuse_buf fbuf = {};

	int res = fuse_session_receive_buf(m_fuseSession, &fbuf);

	if (res == -EINTR)
		return;

	// TODO: Handle correctly
	if (res <= 0)
		QCoreApplication::exit(1);

	fuse_session_process_buf(m_fuseSession, &fbuf);
}

void KIOFuseVFS::getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	// TODO: Validity timeout?
	fuse_reply_attr(req, &node->m_stat, 1);
}

void KIOFuseVFS::readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(node->type() > KIOFuseNode::NodeType::LastDirType)
	{
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	std::vector<char> dirbuf;
	for(auto ino : static_cast<KIOFuseDirNode*>(node)->m_childrenInos)
	{
		KIOFuseNode *child = that->m_nodes[ino].get();
		if(!child)
		{
			qWarning() << "Node" << node->m_nodeName << "references nonexistant child";
			continue;
		}

		QByteArray childName = child->m_nodeName.toUtf8();

		size_t oldsize = dirbuf.size();
		dirbuf.resize(oldsize + fuse_add_direntry(req, nullptr, 0, childName, nullptr, 0));
		fuse_add_direntry(req, dirbuf.data() + oldsize, dirbuf.size() + oldsize, childName, &child->m_stat, dirbuf.size());
	}

	if(off < dirbuf.size())
		fuse_reply_buf(req, dirbuf.data() + off, std::min(size, dirbuf.size() - off));
	else
		fuse_reply_buf(req, nullptr, 0);
}

void KIOFuseVFS::lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(node->type() > KIOFuseNode::NodeType::LastDirType)
	{
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	// Zero means invalid entry. Compared to an ENOENT reply, the kernel can cache this.
	struct fuse_entry_param entry {};

	for(auto ino : static_cast<KIOFuseDirNode*>(node)->m_childrenInos)
	{
		KIOFuseNode *child = that->m_nodes[ino].get();
		if(!child)
		{
			qWarning() << "Node" << node->m_nodeName << "references nonexistant child";
			continue;
		}

		if(qstrcmp(child->m_nodeName.toLocal8Bit(), name) != 0)
			continue;

		// Found
		child->m_lookupCount++;
		entry.ino = ino;
		entry.attr_timeout = 1.0;
		entry.entry_timeout = 1.0;
		entry.attr = child->m_stat;
		break;
	}

	fuse_reply_entry(req, &entry);
}

void KIOFuseVFS::forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(node)
		node->m_lookupCount -= nlookup;

	fuse_reply_none(req);
}

KIOFuseNode *KIOFuseVFS::nodeForIno(const fuse_ino_t ino)
{
	auto it = m_nodes.find(ino);
	if(it == m_nodes.end())
		return nullptr;

	return it->second.get();
}
