#include <unistd.h>
#include <sys/types.h>

#include <QDebug>

#include <KIO/ListJob>
#include <KIO/StatJob>
#include <KIO/TransferJob>

#include "debug.h"
#include "kiofusevfs.h"

// The libfuse macros make this necessary
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
const struct fuse_lowlevel_ops KIOFuseVFS::fuse_ll_ops = {
	.lookup = &KIOFuseVFS::lookup,
	.forget = &KIOFuseVFS::forget,
	.getattr = &KIOFuseVFS::getattr,
	.setattr = &KIOFuseVFS::setattr,
	.readlink = &KIOFuseVFS::readlink,
	.mknod = &KIOFuseVFS::mknod,
	.symlink = &KIOFuseVFS::symlink,
	.open =  &KIOFuseVFS::open,
	.read = &KIOFuseVFS::read,
	.write = &KIOFuseVFS::write,
	.flush = &KIOFuseVFS::flush,
	.fsync = &KIOFuseVFS::fsync,
	.readdir = &KIOFuseVFS::readdir,
};
#pragma GCC diagnostic pop

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
	// Flush all dirty nodes
	QEventLoop loop;
	bool needEventLoop = false;

	for(auto it = m_dirtyNodes.begin(); it != m_dirtyNodes.end();)
	{
		KIOFuseNode *node = nodeForIno(*it);

		++it; // Increment now as flushRemoteNode invalidates the iterator

		KIOFuseRemoteFileNode *remoteNode;
		if(!node || !(remoteNode = node->as<KIOFuseRemoteFileNode>()) || !remoteNode->m_cacheDirty)
		{
			qWarning(KIOFUSE_LOG) << "Broken inode in dirty set";
			continue;
		}

		auto lockerPointer = std::make_shared<QEventLoopLocker>(&loop);
		flushRemoteNode(remoteNode, [lp = std::move(lockerPointer)](int error) {
			if(error)
				qWarning(KIOFUSE_LOG) << "Failed to flush node";
		});

		needEventLoop = true;
	}

	if(needEventLoop)
		loop.exec(); // Wait until all QEventLoopLockers got destroyed

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
				qWarning(KIOFUSE_LOG) << "Error reading FUSE request:" << strerror(errno);

			// Error or umounted -> quit
			stop();
			break;
		}

		fuse_session_process_buf(m_fuseSession, &fbuf);
	}
}

void KIOFuseVFS::getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	that->replyAttr(req, node);
}

void KIOFuseVFS::setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, fuse_file_info *fi)
{
	Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	switch(node->type())
	{
	default:
		fuse_reply_err(req, EOPNOTSUPP);
		return;
	case KIOFuseNode::NodeType::RemoteFileNode:
	{
		auto *remoteNode = node->as<KIOFuseRemoteFileNode>();
		if(to_set & ~(FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID
		              | FUSE_SET_ATTR_MODE)) // Unsupported operation requested?
		{
			// Don't do anything
			fuse_reply_err(req, EOPNOTSUPP);
			return;
		}

		// Can anything be done directly?

		if(to_set & FUSE_SET_ATTR_SIZE)
		{
			// Can be done directly if the new size is zero (and there is no get going on).
			// This is an optimization to avoid fetching the entire file just to ignore its content.
			if(!remoteNode->m_localCache && attr->st_size == 0)
			{
				// Just create an empty file
				remoteNode->m_localCache = tmpfile();
				remoteNode->m_cacheSize = remoteNode->m_stat.st_size = 0;
				remoteNode->m_cacheDirty = true;

				to_set &= ~FUSE_SET_ATTR_SIZE; // Done already!
			}
		}

		if(!to_set) // Done already?
		{
			replyAttr(req, node);
			return;
		}

		// Everything else has to be done async - but there might be multiple ops that
		// need to be coordinated. If an operation completes and clearing its value(s)
		// in to_set_remaining leaves a zero value, it replies with fuse_reply_attr if
		// error is zero and fuse_reply_err(error) otherwise.
		struct SetattrState {
			int to_set_remaining;
			int error;
			struct stat value;
		};

		auto sharedState = std::make_shared<SetattrState>((SetattrState){to_set, 0, *attr});

		if(to_set & FUSE_SET_ATTR_SIZE)
		{
			// Have to wait until the cache is complete to truncate.
			// Waiting until all bytes up to the truncation point are available won't work,
			// as the fetch function would just overwrite the cache.
			that->waitUntilBytesAvailable(remoteNode, SIZE_MAX, [=](int error) {
				if(error && error != ESPIPE)
					sharedState->error = error;
				else // Cache complete!
				{
					// Truncate the cache file
					if(fflush(remoteNode->m_localCache) != 0
					    || ftruncate(fileno(remoteNode->m_localCache), sharedState->value.st_size) == -1)
						sharedState->error = errno;
					else
					{
						remoteNode->m_cacheSize = remoteNode->m_stat.st_size = sharedState->value.st_size;
						remoteNode->m_cacheDirty = true;
					}
				}

				sharedState->to_set_remaining &= ~FUSE_SET_ATTR_SIZE;
				if(!sharedState->to_set_remaining)
				{
					if(sharedState->error)
						fuse_reply_err(req, sharedState->error);
					else
						replyAttr(req, remoteNode);
				}
			});
		}

		if(to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))
		{
			// KIO uses strings for passing user and group, but the VFS uses IDs exclusively.
			// So this needs a roundtrip.

			uid_t newUid = (to_set & FUSE_SET_ATTR_UID) ? attr->st_uid : node->m_stat.st_uid;
			gid_t newGid = (to_set & FUSE_SET_ATTR_GID) ? attr->st_gid : node->m_stat.st_gid;
			auto *pw = getpwuid(newUid);
			auto *gr = getgrgid(newGid);

			if(!pw || !gr)
			{
				sharedState->to_set_remaining &= ~(FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID);
				sharedState->error = ENOENT;
			}
			else
			{
				QString newOwner = QString::fromUtf8(pw->pw_name),
				        newGroup = QString::fromUtf8(gr->gr_name);

				auto url = node->remoteUrl([that](auto ino) { return that->nodeForIno(ino); });
				auto *job = KIO::chown(url, newOwner, newGroup);
				that->connect(job, &KIO::SimpleJob::finished, [=] {
					if(job->error())
						sharedState->error = EIO;
					else
					{
						remoteNode->m_stat.st_uid = newUid;
						remoteNode->m_stat.st_gid = newGid;
					}

					sharedState->to_set_remaining &= ~(FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID);
					if(!sharedState->to_set_remaining)
					{
						if(sharedState->error)
							fuse_reply_err(req, sharedState->error);
						else
							replyAttr(req, remoteNode);
					}
				});
			}
		}

		if(to_set & (FUSE_SET_ATTR_MODE))
		{
			auto url = node->remoteUrl([that](auto ino) { return that->nodeForIno(ino); });
			auto newMode = attr->st_mode & ~S_IFMT;
			auto *job = KIO::chmod(url, newMode);
			that->connect(job, &KIO::SimpleJob::finished, [=] {
				if(job->error())
					sharedState->error = EIO;
				else
					remoteNode->m_stat.st_mode = (remoteNode->m_stat.st_mode & S_IFMT) | newMode;

				sharedState->to_set_remaining &= ~FUSE_SET_ATTR_MODE;
				if(!sharedState->to_set_remaining)
				{
					if(sharedState->error)
						fuse_reply_err(req, sharedState->error);
					else
						replyAttr(req, remoteNode);
				}
			});
		}
	}
	}
}

void KIOFuseVFS::readlink(fuse_req_t req, fuse_ino_t ino)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(node->type() != KIOFuseNode::NodeType::RemoteSymlinkNode)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	fuse_reply_readlink(req, node->as<KIOFuseSymLinkNode>()->m_target.toUtf8().data());
}

void KIOFuseVFS::mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	Q_UNUSED(rdev);

	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	KIOFuseRemoteDirNode *remote = node->as<KIOFuseRemoteDirNode>();
	if(!remote)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	// No type means regular file as well
	if((mode & S_IFMT) != S_IFREG && (mode & S_IFMT) != 0)
	{
		fuse_reply_err(req, EOPNOTSUPP);
		return;
	}

	auto url = node->remoteUrl([that](auto ino) { return that->nodeForIno(ino); });
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	auto *job = KIO::put(url, mode & ~S_IFMT);
	// Not connecting to the dataReq signal at all results in an empty file
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->mountUrl(url, [=](KIOFuseNode *node, int error) {
			if(error)
			{
				fuse_reply_err(req, error);
				return;
			}

			node->m_lookupCount++;

			struct fuse_entry_param entry {};
			entry.ino = node->m_stat.st_ino;
			entry.attr_timeout = 1.0;
			entry.entry_timeout = 1.0;
			entry.attr = node->m_stat;

			fuse_reply_entry(req, &entry);
		});
	});
}

void KIOFuseVFS::symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	KIOFuseRemoteDirNode *remote = node->as<KIOFuseRemoteDirNode>();
	if(!remote)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto url = node->remoteUrl([that](auto ino) { return that->nodeForIno(ino); });
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	auto *job = KIO::symlink(QString::fromUtf8(link), url);
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->mountUrl(url, [=](KIOFuseNode *node, int error) {
			if(error)
			{
				fuse_reply_err(req, error);
				return;
			}

			node->m_lookupCount++;

			struct fuse_entry_param entry {};
			entry.ino = node->m_stat.st_ino;
			entry.attr_timeout = 1.0;
			entry.entry_timeout = 1.0;
			entry.attr = node->m_stat;

			fuse_reply_entry(req, &entry);
		});
	});
}

void KIOFuseVFS::open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
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
		fuse_reply_open(req, fi);
		return;
	case KIOFuseNode::NodeType::RemoteFileNode:
	{
		auto *remoteNode = node->as<KIOFuseRemoteFileNode>();
		if(fi->flags & O_TRUNC)
		{
			if(!remoteNode->m_localCache || remoteNode->cacheIsComplete())
			{
				// Cache not filled - just create an empty file
				if(remoteNode->m_localCache)
					fclose(remoteNode->m_localCache);

				// Create a mew the cache file
				remoteNode->m_localCache = tmpfile();
				remoteNode->m_cacheSize = remoteNode->m_stat.st_size = 0;
				remoteNode->m_cacheDirty = true;
			}
			else if(!remoteNode->cacheIsComplete())
			{
				// Cache is being filled - wait until complete
				// Using a unique_ptr here to let the lambda disconnect the connection itself
				auto connection = std::make_unique<QMetaObject::Connection>();
				auto &conn = *connection;
				conn = that->connect(remoteNode, &KIOFuseRemoteFileNode::localCacheChanged,
				               [=, connection = std::move(connection)](int error) {
					if(error)
					{
						fuse_reply_err(req, error);
						remoteNode->disconnect(conn);
					}
					else if(remoteNode->cacheIsComplete())
					{
						// Create a new empty cache file
						fclose(remoteNode->m_localCache);
						remoteNode->m_localCache = tmpfile();
						remoteNode->m_cacheSize = remoteNode->m_stat.st_size = 0;
						remoteNode->m_cacheDirty = true;

						fuse_reply_open(req, fi);
						remoteNode->disconnect(conn);
					}
				});
				return;
			}
			else
				Q_ASSERT(false);
		}

		fuse_reply_open(req, fi);
	}
	}
}

static void appendDirentry(std::vector<char> &dirbuf, fuse_req_t req, const char *name, const struct stat *stbuf)
{
	size_t oldsize = dirbuf.size();
	dirbuf.resize(oldsize + fuse_add_direntry(req, nullptr, 0, name, nullptr, 0));
	fuse_add_direntry(req, dirbuf.data() + oldsize, dirbuf.size() + oldsize, name, stbuf, dirbuf.size());
}

void KIOFuseVFS::readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi)
{
	Q_UNUSED(fi);
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
				qWarning(KIOFUSE_LOG) << "Node" << node->m_nodeName << "references nonexistant child";
				continue;
			}

			appendDirentry(dirbuf, req, qPrintable(child->m_nodeName), &child->m_stat);
		}

		if(off < off_t(dirbuf.size()))
			fuse_reply_buf(req, dirbuf.data() + off, std::min(size, dirbuf.size() - off));
		else
			fuse_reply_buf(req, nullptr, 0);
	});
}

void KIOFuseVFS::read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi)
{
	Q_UNUSED(fi);
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
				if(off >= off_t(remoteNode->m_cacheSize))
					actualSize = 0;
				else
					actualSize = std::min(remoteNode->m_cacheSize - off, size);
			}

			// Make sure that the kernel has the data
			fflush(remoteNode->m_localCache);

			// Construct a buf pointing to the cache file
			fuse_bufvec buf = FUSE_BUFVEC_INIT(actualSize);
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
	Q_UNUSED(fi);
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
	case KIOFuseNode::NodeType::RemoteFileNode:
	{
		QByteArray data(buf, size); // Copy data
		auto *remoteNode = node->as<KIOFuseRemoteFileNode>();
		that->waitUntilBytesAvailable(remoteNode, off + size, [=](int error) {
			if(error && error != ESPIPE)
			{
				fuse_reply_err(req, error);
				return;
			}

			if(fseek(remoteNode->m_localCache, off, SEEK_SET) == -1
			   || !sane_fwrite(data.data(), data.size(), remoteNode->m_localCache))
			{
				fuse_reply_err(req, errno);
				return;
			}

			remoteNode->m_cacheSize = std::max(remoteNode->m_cacheSize, off + size);
			remoteNode->m_stat.st_size = remoteNode->m_cacheSize;

			remoteNode->m_cacheDirty = true;
			that->m_dirtyNodes.insert(node->m_stat.st_ino);

			fuse_reply_write(req, data.size());
		});
	}
	}
}

void KIOFuseVFS::flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	// This is called on each close of a FD, so it might be a bit overzealous
	// do writeback here. I can't think of a better alternative though -
	// doing it only on fsync and the final forget seems like a bit too late.

	return fsync(req, ino, 1, fi);
}

void KIOFuseVFS::fsync(fuse_req_t req, fuse_ino_t ino, int datasync, fuse_file_info *fi)
{
	Q_UNUSED(datasync); Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	KIOFuseNode *node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto *remoteNode = node->as<KIOFuseRemoteFileNode>();
	if(!remoteNode)
	{
		fuse_reply_err(req, 0);
		return;
	}

	that->flushRemoteNode(remoteNode, [=](int error) {
		fuse_reply_err(req, error);
	});
}

KIOFuseNode *KIOFuseVFS::nodeByName(const KIOFuseNode *parent, const QString name)
{
	for(auto ino : parent->as<KIOFuseDirNode>()->m_childrenInos)
	{
		KIOFuseNode *child = m_nodes[ino].get();
		if(!child)
		{
			qWarning(KIOFUSE_LOG) << "Node" << parent->m_nodeName << "references nonexistant child";
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

	QString nodeName = QString::fromUtf8(name);

	if(auto child = that->nodeByName(parentNode, nodeName))
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

		if(auto child = that->nodeByName(parentNode, nodeName))
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
		qWarning(KIOFUSE_LOG) << "Tried to insert node with invalid parent";

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
	attr.st_blksize = 512;
	// This is set to match st_size by replyAttr
	attr.st_blocks = 1;

	clock_gettime(CLOCK_REALTIME, &attr.st_atim);
	attr.st_mtim = attr.st_atim;
	attr.st_ctim = attr.st_atim;
}

void KIOFuseVFS::replyAttr(fuse_req_t req, KIOFuseNode *node)
{
	// Set st_blocks accordingly
	node->m_stat.st_blocks = (node->m_stat.st_size + node->m_stat.st_blksize - 1) / node->m_stat.st_blksize;

	// TODO: Validity timeout?
	fuse_reply_attr(req, &node->m_stat, 1);
}

KIOFuseNode *KIOFuseVFS::createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno, QString nameOverride)
{
	QString name = nameOverride;
	if(name.isEmpty())
		name = entry.stringValue(KIO::UDSEntry::UDS_NAME);
	if(name.isEmpty() || name.contains(QLatin1Char('/'))
	   || name == QStringLiteral(".") || name == QStringLiteral(".."))
		return nullptr; // Reject invalid names

	// Create a stat struct with default values
	struct stat attr = {};
	fillStatForFile(attr);
	attr.st_size = entry.numberValue(KIO::UDSEntry::UDS_SIZE, 1);
	attr.st_mode = entry.numberValue(KIO::UDSEntry::UDS_ACCESS, entry.isDir() ? 0755 : 0644);
	if(entry.contains(KIO::UDSEntry::UDS_MODIFICATION_TIME))
	{
		attr.st_mtim.tv_sec = entry.numberValue(KIO::UDSEntry::UDS_MODIFICATION_TIME);
		attr.st_mtim.tv_nsec = 0;
	}
	if(entry.contains(KIO::UDSEntry::UDS_ACCESS_TIME))
	{
		attr.st_atim.tv_sec = entry.numberValue(KIO::UDSEntry::UDS_ACCESS_TIME);
		attr.st_atim.tv_nsec = 0;
	}
	// No support for ctim/btim in KIO...

	// Setting UID and GID here to UDS_USER/UDS_GROUP respectively does not lead to the expected
	// results as those values might only be meaningful on the remote side.
	// As access checks are only performed by the remote side, it shouldn't matter much though.
	// It's necessary to make chown/chmod meaningful.
	if(entry.contains(KIO::UDSEntry::UDS_USER))
	{
		QString user = entry.stringValue(KIO::UDSEntry::UDS_USER);
		auto *pw = getpwnam(user.toUtf8().data());
		if(pw)
			attr.st_uid = pw->pw_uid;
	}
	if(entry.contains(KIO::UDSEntry::UDS_GROUP))
	{
		QString group = entry.stringValue(KIO::UDSEntry::UDS_GROUP);
		auto *gr = getgrnam(group.toUtf8().data());
		if(gr)
			attr.st_gid = gr->gr_gid;
	}

	if(entry.contains(KIO::UDSEntry::UDS_LOCAL_PATH) || entry.contains(KIO::UDSEntry::UDS_URL))
	{
		// Create as symlink if possible
		QString target = entry.stringValue(KIO::UDSEntry::UDS_LOCAL_PATH);
		if(target.isEmpty())
			target = QUrl(entry.stringValue(KIO::UDSEntry::UDS_URL)).toLocalFile();

		if(!target.isEmpty())
		{
			// Symlink to local file/folder
			attr.st_mode |= S_IFLNK;
			auto *ret = new KIOFuseSymLinkNode(parentIno, name, attr);
			ret->m_target = target;
			ret->m_stat.st_size = ret->m_target.toUtf8().length();
			return ret;
		}
		else if(entry.isLink())
			return nullptr; // Does this even happen?
		else if(entry.isDir())
			return nullptr; // Maybe create a mountpoint (OriginNode) here?
		else // Regular file pointing to URL
		{
			attr.st_mode |= S_IFREG;
			auto *ret = new KIOFuseRemoteFileNode(parentIno, name, attr);
			ret->m_overrideUrl = QUrl{entry.stringValue(KIO::UDSEntry::UDS_URL)};
			return ret;
		}
	}
	else if(entry.isLink())	// Check for link first as isDir can also be a link
	{
		attr.st_mode |= S_IFLNK;
		auto *ret = new KIOFuseSymLinkNode(parentIno, name, attr);
		ret->m_target = entry.stringValue(KIO::UDSEntry::UDS_LINK_DEST);
		attr.st_size = ret->m_target.size();
		return ret;
	}
	else if(entry.isDir())
	{
		attr.st_mode |= S_IFDIR;
		return new KIOFuseRemoteDirNode(parentIno, name, attr);
	}
	else // it's a regular file
	{
		attr.st_mode |= S_IFREG;
		return new KIOFuseRemoteFileNode(parentIno, name, attr);
	}
}

void KIOFuseVFS::waitUntilBytesAvailable(KIOFuseRemoteFileNode *node, size_t bytes, std::function<void(int error)> callback)
{
	if(node->m_localCache && node->m_cacheSize >= bytes)
		return callback(0); // Already available
	else if(node->cacheIsComplete()) // Full cache is available...
		return callback(ESPIPE); // ...but less than requested.

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
				// Might be different from the attr size meanwhile, use the more recent value.
				// This also ensures that the cache is seen as complete.
				node->m_stat.st_size = node->m_cacheSize;
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

		if(node->m_cacheSize >= bytes) // Requested data available
		{
			callback(0);
			node->disconnect(*connection);
		}
		else if(node->cacheIsComplete()) // Full cache is available...
		{
			// ...but less than requested.
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
				if(name == QStringLiteral(".") || name == QStringLiteral(".."))
				   continue;

				KIOFuseNode *childrenNode = nodeByName(remoteNode, name);
				if(childrenNode)
					// TODO: Verify that the type matches.
					// It's possible that something was mounted as a directory,
					// but it's actually a symlink :-/
					continue;

				childrenNode = createNodeFromUDSEntry(entry, remoteNode->m_stat.st_ino);
				if(!childrenNode)
				{
					qWarning(KIOFUSE_LOG) << "Could not create node for" << name;
					continue;
				}

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

void KIOFuseVFS::mountUrl(QUrl url, std::function<void (KIOFuseNode *, int)> callback)
{
	qDebug(KIOFUSE_LOG) << "Mounting url" << url;
	auto statJob = KIO::stat(url);
	statJob->setSide(KIO::StatJob::SourceSide); // Be "optimistic" to allow accessing
	                                            // files over plain HTTP
	connect(statJob, &KIO::StatJob::result, [=] {
		if(statJob->error())
		{
			qDebug(KIOFUSE_LOG) << statJob->errorString();
			callback(nullptr, EIO);
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
			// Find out whether the base URL needs to start with a /
			if(url.path().startsWith(QLatin1Char('/')))
				(originNode->as<KIOFuseOriginNode>()->m_baseUrl = url).setPath(QStringLiteral("/"));
			else
				(originNode->as<KIOFuseOriginNode>()->m_baseUrl = url).setPath({});
			originNode->m_stat.st_ino = insertNode(originNode);
		}

		// Create all path components as directories
		KIOFuseNode *pathNode = originNode;
		auto pathElements = url.path().split(QLatin1Char('/'));

		// Strip empty path elements, for instance in
		// "file:///home/foo"
		// "ftp://dir/ectory/"
		pathElements.removeAll({});

		if(pathElements.size() == 0)
		{
			callback(pathNode, 0);
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
			// The remote name (statJob->statResult().stringValue(KIO::UDSEntry::UDS_NAME)) has to be
			// ignored as it can be different from the path. e.g. tar:/foo.tar/ is "/"
			finalNode = createNodeFromUDSEntry(statJob->statResult(), pathNode->m_stat.st_ino, pathElements.last());
			if(!finalNode)
				return callback(nullptr, EIO);

			finalNode->m_stat.st_ino = insertNode(finalNode);
		}

		callback(finalNode, 0);
	});
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
		if(url.isValid())
			return mountUrl(url, [=](KIOFuseNode *node, int error) {
				Q_UNUSED(node);
				callback(error ? EINVAL : 0);
			});
		else
			return callback(EINVAL);
	}
	else
	{
		qWarning(KIOFUSE_LOG) << "Unknown control operation" << op;
		return callback(EINVAL);
	}
}

void KIOFuseVFS::flushRemoteNode(KIOFuseRemoteFileNode *node, std::function<void (int)> callback)
{
	if(!node->m_cacheDirty)
		return callback(0);

	qDebug(KIOFUSE_LOG) << "Flushing node" << node->m_nodeName;

	// Clear the flag now to not lose any writes that happen while sending data.
	node->m_cacheDirty = false;
	m_dirtyNodes.extract(node->m_stat.st_ino);

	auto url = node->remoteUrl([this](auto ino) { return nodeForIno(ino); });
	auto *job = KIO::put(url, node->m_stat.st_mode & ~S_IFMT, KIO::Overwrite);
	job->setTotalSize(node->m_cacheSize);

	size_t bytesSent = 0; // Modified inside the lambda
	connect(job, &KIO::TransferJob::dataReq, [=](auto *job, QByteArray &data) mutable {
		Q_UNUSED(job);

		// Someone truncated the file?
		if(node->m_cacheSize <= bytesSent)
			return;

		size_t toSend = std::min(node->m_cacheSize - bytesSent, 1024*1024ul); // 1MiB max
		data.resize(toSend);

		// Read the cache file into the buffer
		if(fseek(node->m_localCache, bytesSent, SEEK_SET) == -1
		   || !sane_fread(data.data(), toSend, node->m_localCache))
		{
			qWarning(KIOFUSE_LOG) << "Failed to read cache:" << strerror(errno);
			job->kill(KJob::EmitResult);
			return;
		}

		bytesSent += toSend;
	});
	connect(job, &KIO::TransferJob::result, [=] {
		if(job->error())
		{
			qWarning(KIOFUSE_LOG) << "Failed to send data:" << job->errorString();
			node->m_cacheDirty = true;
			m_dirtyNodes.insert(node->m_stat.st_ino);
			return callback(EIO);
		}

		callback(0);
	});
}
