#include <unistd.h>
#include <sys/types.h>

#include <QDebug>

#include <KIO/ListJob>
#include <KIO/StatJob>
#include <KIO/TransferJob>

#include "kiofusevfs.h"

const struct fuse_lowlevel_ops KIOFuseVFS::fuse_ll_ops = {
	.lookup = &KIOFuseVFS::lookup,
	.forget = &KIOFuseVFS::forget,
	.getattr = &KIOFuseVFS::getattr,
	.read = &KIOFuseVFS::read,
	.write = &KIOFuseVFS::write,
	.readdir = &KIOFuseVFS::readdir,
};

/* Handles partial writes.
 * Returns true only if count bytes were written successfully. */
static bool sane_fwrite(const char *buf, size_t count, FILE *fd)
{
	while(count)
	{
		size_t step = fwrite(buf, 1, count, fd);
		if(step == 0)
			return false;

		count -= step;
		buf += step;
	}

	return true;
}

/* Handles partial reads.
 * Returns true only if count bytes were read successfully. */
static bool sane_fread(char *buf, size_t count, FILE *fd)
{
	while(count)
	{
		size_t step = fread(buf, 1, count, fd);
		if(step == 0)
			return false;

		count -= step;
		buf += step;
	}

	return true;
}

KIOFuseVFS::KIOFuseVFS(QObject *parent)
    : QObject(parent)
{
	struct stat attr = {};
	fillStatForFile(attr);
	attr.st_mode = S_IFDIR | 0755;

	// TODO: Add insert function?
	auto root = std::make_unique<KIOFuseRootNode>(KIOFuseIno::Invalid, QString(), attr);
	root->m_stat.st_ino = KIOFuseIno::Root;

	auto control = std::make_unique<KIOFuseControlNode>(KIOFuseIno::Root, QStringLiteral("_control"), attr);
	control->m_stat.st_ino = KIOFuseIno::Control;
	control->m_stat.st_mode = S_IFREG | 0700;

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

	// Setup a notifier on the FUSE FD
	int fusefd = fuse_session_fd(m_fuseSession);

	// Set the FD to O_NONBLOCK so that it can be read in a loop until empty
	int flags = fcntl(fusefd, F_GETFL);
	fcntl(fusefd, F_SETFL, flags | O_NONBLOCK);

	m_fuseNotifier = std::make_unique<QSocketNotifier>(fusefd, QSocketNotifier::Read, this);
	m_fuseNotifier->connect(m_fuseNotifier.get(), &QSocketNotifier::activated, this, &KIOFuseVFS::fuseRequestPending);

	// Arm the QEventLoopLocker
	m_eventLoopLocker = std::make_unique<QEventLoopLocker>();

	return true;
}

void KIOFuseVFS::stop()
{
	if(m_fuseSession)
	{
		// Disable the QSocketNotifier
		m_fuseNotifier.reset();

		// Disarm the QEventLoopLocker
		m_eventLoopLocker.reset();

		fuse_remove_signal_handlers(m_fuseSession);
		fuse_session_unmount(m_fuseSession);
		fuse_session_destroy(m_fuseSession);
		m_fuseSession = nullptr;
	}
}

void KIOFuseVFS::fuseRequestPending()
{
	// Never deallocated, just reused
	static struct fuse_buf fbuf = {};

	// Read requests until empty (-EAGAIN) or error
	for(;;)
	{
		int res = fuse_session_receive_buf(m_fuseSession, &fbuf);

		if (res == -EINTR || res == -EAGAIN)
			break;

		if (res <= 0)
		{
			if(res < 0) // Error
				qWarning() << "Error reading FUSE request:" << strerror(errno);

			// Error or umounted -> quit
			stop();
			break;
		}

		fuse_session_process_buf(m_fuseSession, &fbuf);
	}
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

static void appendDirentry(std::vector<char> &dirbuf, fuse_req_t req, const char *name, const struct stat *stbuf)
{
	size_t oldsize = dirbuf.size();
	dirbuf.resize(oldsize + fuse_add_direntry(req, nullptr, 0, name, nullptr, 0));
	fuse_add_direntry(req, dirbuf.data() + oldsize, dirbuf.size() + oldsize, name, stbuf, dirbuf.size());
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

	that->waitUntilChildrenComplete(node->as<KIOFuseDirNode>(), [=](int error){
		if(error)
		{
			fuse_reply_err(req, error);
			return;
		}

		std::vector<char> dirbuf;
		appendDirentry(dirbuf, req, ".", &node->m_stat);

		KIOFuseNode *parentNode = that->nodeForIno(node->m_parentIno);
		if(!parentNode)
			parentNode = that->nodeForIno(KIOFuseIno::Root);
		if(parentNode)
			appendDirentry(dirbuf, req, "..", &parentNode->m_stat);

		for(auto ino : node->as<KIOFuseDirNode>()->m_childrenInos)
		{
			KIOFuseNode *child = that->m_nodes[ino].get();
			if(!child)
			{
				qWarning() << "Node" << node->m_nodeName << "references nonexistant child";
				continue;
			}

			appendDirentry(dirbuf, req, qPrintable(child->m_nodeName), &child->m_stat);
		}

		if(off < dirbuf.size())
			fuse_reply_buf(req, dirbuf.data() + off, std::min(size, dirbuf.size() - off));
		else
			fuse_reply_buf(req, nullptr, 0);
	});
}

void KIOFuseVFS::read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(node->type() <= KIOFuseNode::NodeType::LastDirType)
	{
		fuse_reply_err(req, EISDIR);
		return;
	}

	switch(node->type())
	{
	default:
		fuse_reply_err(req, EIO);
		return;
	case KIOFuseNode::NodeType::RemoteFileNode:
	{
		auto *remoteNode = node->as<KIOFuseRemoteFileNode>();
		that->waitUntilBytesAvailable(remoteNode, off + size, [=](int error) {
			if(error != 0 && error != ESPIPE)
			{
				fuse_reply_err(req, error);
				return;
			}

			auto actualSize = size;

			if(error == ESPIPE)
			{
				// Reading over the end
				if(off >= remoteNode->m_cacheSize)
					actualSize = 0;
				else
					actualSize = std::min(remoteNode->m_cacheSize - off, size);
			}

			// Construct a buf pointing to the cache file
			fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
			buf.buf[0].fd = fileno(remoteNode->m_localCache);
			buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
			buf.buf[0].pos = off;

			fuse_reply_data(req, &buf, fuse_buf_copy_flags{});
		});
		break;
	}
	case KIOFuseNode::NodeType::ControlNode:
		fuse_reply_buf(req, nullptr, 0);
		break;
	}
}

void KIOFuseVFS::write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, fuse_file_info *fi)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(node->type() <= KIOFuseNode::NodeType::LastDirType)
	{
		fuse_reply_err(req, EISDIR);
		return;
	}

	switch(node->type())
	{
	default:
		fuse_reply_err(req, EIO);
		return;

	case KIOFuseNode::NodeType::ControlNode:
	{
		// Intentionally ignoring the offset here
		QString command = QString::fromUtf8(buf, size);
		that->handleControlCommand(command, [=] (int ret) {
			if(ret)
				fuse_reply_err(req, ret);
			else
				fuse_reply_write(req, size);
		});
		return;
	}
	}
}

KIOFuseNode *KIOFuseVFS::nodeByName(const KIOFuseNode *parent, const QString name)
{
	for(auto ino : parent->as<KIOFuseDirNode>()->m_childrenInos)
	{
		KIOFuseNode *child = m_nodes[ino].get();
		if(!child)
		{
			qWarning() << "Node" << parent->m_nodeName << "references nonexistant child";
			continue;
		}

		if(child->m_nodeName == name)
			return child;
	}

	return nullptr;
}

void KIOFuseVFS::lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *parentNode = that->nodeForIno(parent);
	if(!parentNode)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(parentNode->type() > KIOFuseNode::NodeType::LastDirType)
	{
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	if(auto child = that->nodeByName(parentNode, QString::fromUtf8(name)))
	{
		// Found
		child->m_lookupCount++;

		struct fuse_entry_param entry {};
		entry.ino = child->m_stat.st_ino;
		entry.attr_timeout = 1.0;
		entry.entry_timeout = 1.0;
		entry.attr = child->m_stat;

		fuse_reply_entry(req, &entry);
		return;
	}

	// Not found - try again
	that->waitUntilChildrenComplete(parentNode->as<KIOFuseDirNode>(), [=](int error) {
		if(error)
		{
			fuse_reply_err(req, error);
			return;
		}

		// Zero means invalid entry. Compared to an ENOENT reply, the kernel can cache this.
		struct fuse_entry_param entry {};

		if(auto child = that->nodeByName(parentNode, QString::fromUtf8(name)))
		{
			// Found
			child->m_lookupCount++;

			entry.ino = child->m_stat.st_ino;
			entry.attr_timeout = 1.0;
			entry.entry_timeout = 1.0;
			entry.attr = child->m_stat;
		}

		fuse_reply_entry(req, &entry);
	});
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

fuse_ino_t KIOFuseVFS::insertNode(KIOFuseNode *node)
{
	// Allocate a free inode number
	fuse_ino_t ino = m_nextIno;
	while(m_nodes.find(ino) != m_nodes.end())
		ino++;

	m_nextIno = ino + 1;

	m_nodes[ino].reset(node);

	// Adjust internal ino
	node->m_stat.st_ino = ino;

	// Add to parent's child
	auto parentNodeIt = m_nodes.find(node->m_parentIno);
	if(parentNodeIt != m_nodes.end() && parentNodeIt->second->type() <= KIOFuseNode::NodeType::LastDirType)
		parentNodeIt->second.get()->as<KIOFuseDirNode>()->m_childrenInos.push_back(ino);
	else
		qWarning() << "Tried to insert node with invalid parent";

	return ino;
}

void KIOFuseVFS::fillStatForFile(struct stat &attr)
{
	static uid_t uid = getuid();
	static gid_t gid = getgid();

	attr.st_nlink = 1;
	attr.st_mode = S_IFREG | 0755;
	attr.st_uid = uid;
	attr.st_gid = gid;
	attr.st_size = 1;
	attr.st_blksize = 4096;
	attr.st_blocks = 1;

	clock_gettime(CLOCK_REALTIME, &attr.st_atim);
	attr.st_mtim = attr.st_atim;
	attr.st_ctim = attr.st_ctim;
}

KIOFuseNode *KIOFuseVFS::createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno)
{
	if(!entry.contains(KIO::UDSEntry::UDS_NAME))
		return nullptr;

	// TODO: Copy comment from kiofuse here that explains why 755 is necessary here

	// Create a stat struct with default values
	struct stat attr = {};
	fillStatForFile(attr);
	attr.st_size = entry.numberValue(KIO::UDSEntry::UDS_SIZE, 1);
	attr.st_mode = entry.numberValue(KIO::UDSEntry::UDS_ACCESS, entry.isDir() ? 0755 : 0644);

	// Check for link first as isDir can also be a link
	if(entry.isLink())
	{
		attr.st_mode |= S_IFLNK;
		auto *ret = new KIOFuseSymLinkNode(parentIno, entry.stringValue(KIO::UDSEntry::UDS_NAME), attr);
		ret->m_target = entry.stringValue(KIO::UDSEntry::UDS_LINK_DEST);
		attr.st_size = ret->m_target.size();
		return ret;
	}
	else if(entry.isDir())
	{
		attr.st_mode |= S_IFDIR;
		return new KIOFuseRemoteDirNode(parentIno, entry.stringValue(KIO::UDSEntry::UDS_NAME), attr);
	}
	else // it's a regular file
	{
		attr.st_mode |= S_IFREG;
		return new KIOFuseRemoteFileNode(parentIno, entry.stringValue(KIO::UDSEntry::UDS_NAME), attr);
	}
}

void KIOFuseVFS::waitUntilBytesAvailable(KIOFuseRemoteFileNode *node, size_t bytes, std::function<void(int error)> callback)
{
	if(node->m_cacheSize >= bytes)
		return callback(0); // Already available
	else if(node->m_cacheComplete)
		return callback(ESPIPE); // File shorter than bytes

	if(!node->m_localCache)
	{
		// Create a temporary file
		node->m_localCache = tmpfile();

		if(!node->m_localCache)
			return callback(errno);

		// Request the file
		auto url = node->remoteUrl([this](auto ino) { return nodeForIno(ino); });
		auto *job = KIO::get(url);
		connect(job, &KIO::TransferJob::data, [=](auto *job, const QByteArray &data) {
			Q_UNUSED(job);

			if(fseek(node->m_localCache, 0, SEEK_END) == -1
			   || !sane_fwrite(data.data(), data.size(), node->m_localCache))
				emit node->localCacheChanged(errno);
			else
			{
				node->m_cacheSize += data.size();
				emit node->localCacheChanged(0);
			}
		});
		connect(job, &KIO::TransferJob::result, [=] {
			if(job->error())
			{
				fclose(node->m_localCache);
				node->m_localCache = nullptr;
				emit node->localCacheChanged(EIO);
			}
			else
			{
				node->m_cacheComplete = true;
				emit node->localCacheChanged(0);
			}
		});
	}

	// Using a unique_ptr here to let the lambda disconnect the connection itself
	auto connection = std::make_unique<QMetaObject::Connection>();
	auto &conn = *connection;
	conn = connect(node, &KIOFuseRemoteFileNode::localCacheChanged,
	               [=, connection = std::move(connection)](int error) {
		if(error)
		{
			callback(error);
			node->disconnect(*connection);
		}

		if(node->m_cacheSize >= bytes)
		{
			callback(0);
			node->disconnect(*connection);
		}
		else if(node->m_cacheComplete)
		{
			callback(ESPIPE);
			node->disconnect(*connection);
		}
	}
	);
}

void KIOFuseVFS::waitUntilChildrenComplete(KIOFuseDirNode *node, std::function<void (int)> callback)
{
	KIOFuseRemoteDirNode *remoteNode = node->as<KIOFuseRemoteDirNode>();
	if(!remoteNode)
		return callback(0); // Not a remote node

	if(remoteNode->m_childrenComplete)
		return callback(0);

	if(!remoteNode->m_childrenRequested)
	{
		// List the remote dir
		auto url = remoteNode->remoteUrl([this](auto ino) { return nodeForIno(ino); });
		auto *job = KIO::listDir(url);
		connect(job, &KIO::ListJob::entries, [=](auto *job, const KIO::UDSEntryList &entries) {
			Q_UNUSED(job);

			for(auto &entry : entries)
			{
				QString name = entry.stringValue(KIO::UDSEntry::UDS_NAME);

				// Ignore "." and ".."
				if(QStringList{QStringLiteral("."), QStringLiteral("..")}.contains(name))
				   continue;

				KIOFuseNode *childrenNode = nodeByName(remoteNode, name);
				if(childrenNode)
					// TODO: Verify that the type matches.
					// It's possible that something was mounted as a directory,
					// but it's actually a symlink :-/
					continue;

				childrenNode = createNodeFromUDSEntry(entry, remoteNode->m_stat.st_ino);
				childrenNode->m_stat.st_ino = insertNode(childrenNode);
			}
		});
		connect(job, &KIO::ListJob::result, [=] {
			remoteNode->m_childrenRequested = false;

			if(job->error())
				emit remoteNode->gotChildren(EIO);
			else
			{
				remoteNode->m_childrenComplete = true;
				emit remoteNode->gotChildren(0);
			}
		});

		remoteNode->m_childrenRequested = true;
	}

	// Using a unique_ptr here to let the lambda disconnect the connection itself
	auto connection = std::make_unique<QMetaObject::Connection>();
	auto &conn = *connection;
	conn = connect(remoteNode, &KIOFuseRemoteDirNode::gotChildren,
	               [=, connection = std::move(connection)](int error) {
		callback(error);
		remoteNode->disconnect(*connection);
	}
	);
}

void KIOFuseVFS::handleControlCommand(QString cmd, std::function<void (int)> callback)
{
	int opEnd = cmd.indexOf(QLatin1Char(' '));
	if(opEnd < 0)
		return callback(EINVAL);

	QStringRef op = cmd.midRef(0, opEnd);
	// Command "MOUNT <url>"
	if(op == QStringLiteral("MOUNT"))
	{
		QUrl url = QUrl{cmd.midRef(opEnd + 1).trimmed().toString()};
		if(!url.isValid())
			return callback(EINVAL);

		auto statJob = KIO::stat(url);
		statJob->setSide(KIO::StatJob::SourceSide); // Be "optimistic" to allow accessing
		                                            // files over plain HTTP
		connect(statJob, &KIO::StatJob::result, [=] {
			if(statJob->error())
			{
				qDebug() << statJob->errorString();
				callback(EINVAL);
				return;
			}

			// Success - create an entry

			KIOFuseNode *rootNode = m_nodes[KIOFuseIno::Root].get();
			KIOFuseNode *protocolNode = rootNode;

			// Depending on whether the URL has an "authority" component or not,
			// the path is mapped differently:
			// file:///home/foo -> mountpoint/file/home/foo
			// ftp://user:pass@server/file -> mountpoint/ftp/user@server/file

			QString originNodeName;

			if(!url.authority().isEmpty())
			{
				// Authority exists -> create a ProtocolNode as intermediate
				protocolNode = nodeByName(rootNode, url.scheme());
				if(!protocolNode)
				{
					struct stat attr = {};
					fillStatForFile(attr);
					attr.st_mode = S_IFDIR | 0755;

					protocolNode = new KIOFuseProtocolNode(KIOFuseIno::Root, url.scheme(), attr);
					protocolNode->m_stat.st_ino = insertNode(protocolNode);
				}

				QUrl urlWithoutPassword = url;
				urlWithoutPassword.setPassword({});

				originNodeName = urlWithoutPassword.authority();
			}
			else
			{
				// No authority -> the scheme itself is used as OriginNode
				originNodeName = url.scheme();
			}

			KIOFuseNode *originNode = nodeByName(protocolNode, originNodeName);
			if(!originNode)
			{
				struct stat attr = {};
				fillStatForFile(attr);
				attr.st_mode = S_IFDIR | 0755;

				originNode = new KIOFuseOriginNode(protocolNode->m_stat.st_ino, originNodeName, attr);
				(originNode->as<KIOFuseOriginNode>()->m_baseUrl = url).setPath({});
				originNode->m_stat.st_ino = insertNode(originNode);
			}

			// Create all path components as directories
			KIOFuseNode *pathNode = originNode;
			auto pathElements = url.path().split(QLatin1Char('/'));

			// Strip empty path elements, for instance in
			// "file:///home/foo"
			// "ftp://dir/ectory/"
			pathElements.removeAll(QStringLiteral(""));

			if(pathElements.size() == 0)
			{
				callback(0);
				return;
			}

			for(int i = 0; pathElements.size() > 1 && i < pathElements.size() - 1; ++i)
			{
				if(pathElements[i].isEmpty())
					break;

				KIOFuseNode *subdirNode = nodeByName(pathNode, pathElements[i]);
				if(!subdirNode)
				{
					struct stat attr = {};
					fillStatForFile(attr);
					attr.st_mode = S_IFDIR | 0755;

					subdirNode = new KIOFuseRemoteDirNode(pathNode->m_stat.st_ino, pathElements[i], attr);
					subdirNode->m_stat.st_ino = insertNode(subdirNode);
				}

				pathNode = subdirNode;
			}

			// Finally create the last component
			KIOFuseNode *finalNode = nodeByName(pathNode, pathElements.last());
			if(!finalNode)
			{
				finalNode = createNodeFromUDSEntry(statJob->statResult(), pathNode->m_stat.st_ino);
				finalNode->m_stat.st_ino = insertNode(finalNode);

				// The remote name (statJob->statResult().stringValue(KIO::UDSEntry::UDS_NAME)) has to be
				// ignored as it can be different from the path. e.g. tar:/foo.tar/ is "/"
				finalNode->m_nodeName = pathElements.last();
			}

			callback(0);
		});
	}
	else
	{
		qWarning() << "Unknown control operation" << op;
		return callback(EINVAL);
	}
}
