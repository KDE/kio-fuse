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

#include <linux/fs.h>
#include <sys/types.h>
#include <unistd.h>

#include <QDateTime>
#include <QDebug>

#include <KIO/ListJob>
#include <KIO/MkdirJob>
#include <KIO/StatJob>
#include <KIO/TransferJob>
#include <KIO/DeleteJob>

#include "debug.h"
#include "kiofusevfs.h"

// The libfuse macros make this necessary
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
const struct fuse_lowlevel_ops KIOFuseVFS::fuse_ll_ops = {
	.init = &KIOFuseVFS::init,
	.lookup = &KIOFuseVFS::lookup,
	.forget = &KIOFuseVFS::forget,
	.getattr = &KIOFuseVFS::getattr,
	.setattr = &KIOFuseVFS::setattr,
	.readlink = &KIOFuseVFS::readlink,
	.mknod = &KIOFuseVFS::mknod,
	.mkdir = &KIOFuseVFS::mkdir,
	.unlink = &KIOFuseVFS::unlink,
	.rmdir = &KIOFuseVFS::rmdir,
	.symlink = &KIOFuseVFS::symlink,
	.rename = &KIOFuseVFS::rename,
	.open = &KIOFuseVFS::open,
	.read = &KIOFuseVFS::read,
	.write = &KIOFuseVFS::write,
	.flush = &KIOFuseVFS::flush,
	.release = &KIOFuseVFS::release,
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

	auto root = std::make_shared<KIOFuseRootNode>(KIOFuseIno::Invalid, QString(), attr);
	insertNode(root, KIOFuseIno::Root);

	auto deletedRoot = std::make_shared<KIOFuseRootNode>(KIOFuseIno::Invalid, QString(), attr);
	insertNode(deletedRoot, KIOFuseIno::DeletedRoot);

	auto control = std::make_shared<KIOFuseControlNode>(KIOFuseIno::Root, QStringLiteral("_control"), attr);
	insertNode(control, KIOFuseIno::Control);
	control->m_stat.st_mode = S_IFREG | 0400;
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

	// Flush all dirty nodes
	QEventLoop loop;
	bool needEventLoop = false;

	for(auto it = m_dirtyNodes.begin(); it != m_dirtyNodes.end();)
	{
		auto node = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(nodeForIno(*it));

		++it; // Increment now as flushRemoteNode invalidates the iterator

		if(!node || (!node->m_cacheDirty && !node->m_flushRunning))
		{
			qWarning(KIOFUSE_LOG) << "Broken inode in dirty set";
			continue;
		}

		auto lockerPointer = std::make_shared<QEventLoopLocker>(&loop);
		// Trigger or wait until flush done.
		awaitNodeFlushed(node, [lp = std::move(lockerPointer)](int) {});

		needEventLoop = true;
	}

	if(needEventLoop)
		loop.exec(); // Wait until all QEventLoopLockers got destroyed
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

void KIOFuseVFS::init(void *userdata, fuse_conn_info *conn)
{
	Q_UNUSED(userdata);

	conn->want &= ~FUSE_CAP_HANDLE_KILLPRIV; // Don't care about resetting setuid/setgid flags
	conn->want &= ~FUSE_CAP_ATOMIC_O_TRUNC; // Use setattr with st_size = 0 instead of open with O_TRUNC
	conn->want |= FUSE_CAP_WRITEBACK_CACHE; // Kernel caches reads/writes, handles O_APPEND and st_[acm]tim
	conn->time_gran = 1000000000; // Only second resolution for mtime
}

void KIOFuseVFS::getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
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
	auto node = that->nodeForIno(ino);
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
	case KIOFuseNode::NodeType::ControlNode:
		// Only truncation to 0 supported
		if((to_set & FUSE_SET_ATTR_SIZE) == FUSE_SET_ATTR_SIZE && attr->st_size == 0)
			replyAttr(req, node);
		else
			fuse_reply_err(req, EOPNOTSUPP);

		return;
	case KIOFuseNode::NodeType::RemoteDirNode:
	case KIOFuseNode::NodeType::RemoteFileNode:
	{
		auto remoteFileNode = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(node);
		if((to_set & ~(FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID
		              | FUSE_SET_ATTR_MODE
		              | FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW
		              | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_ATIME_NOW
		              | FUSE_SET_ATTR_CTIME))
		   || (!remoteFileNode && (to_set & FUSE_SET_ATTR_SIZE))) // Unsupported operation requested?
		{
			// Don't do anything
			fuse_reply_err(req, EOPNOTSUPP);
			return;
		}

		// To have equal atim and mtim
		struct timespec tsNow;
		clock_gettime(CLOCK_REALTIME, &tsNow);

		// Can anything be done directly?

		// This is a hack: Access and change time are not actually passed through to KIO.
		// The kernel sends request for those if writeback caching is enabled, so it's not
		// possible to ignore them. So just save them in the local cache.
		if(to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_ATIME_NOW))
		{
			if(to_set & FUSE_SET_ATTR_ATIME_NOW)
				attr->st_atim = tsNow;

			node->m_stat.st_atim = attr->st_atim;
			to_set &= ~(FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_ATIME_NOW);
		}
		if(to_set & FUSE_SET_ATTR_CTIME)
		{
			node->m_stat.st_ctim = attr->st_ctim;
			to_set &= ~FUSE_SET_ATTR_CTIME;
		}

		if(to_set & FUSE_SET_ATTR_SIZE)
		{
			// Can be done directly if the new size is zero (and there is no get going on).
			// This is an optimization to avoid fetching the entire file just to ignore its content.
			if(!remoteFileNode->m_localCache && attr->st_size == 0)
			{
				// Just create an empty file
				remoteFileNode->m_localCache = tmpfile();
				if(remoteFileNode->m_localCache == nullptr)
				{
					fuse_reply_err(req, EIO);
					// Some part of the operation might've succeeded though, inform the kernel about that
					that->sendNotifyInvalEntry(remoteFileNode);
					return;
				}

				remoteFileNode->m_cacheComplete = true;
				remoteFileNode->m_cacheSize = remoteFileNode->m_stat.st_size = 0;
				that->markCacheDirty(remoteFileNode);

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

		auto markOperationCompleted = [=] (int to_set_done){
			sharedState->to_set_remaining &= ~to_set_done;
			if(!sharedState->to_set_remaining)
			{
				if(sharedState->error)
				{
					fuse_reply_err(req, sharedState->error);
					// Some part of the operation might've succeeded though, inform the kernel about that
					that->sendNotifyInvalEntry(node);
				}
				else
					replyAttr(req, node);
			}
		};

		if(to_set & FUSE_SET_ATTR_SIZE)
		{
			// Have to wait until the cache is complete to truncate.
			// Waiting until all bytes up to the truncation point are available won't work,
			// as the fetch function would just overwrite the cache.
			that->awaitBytesAvailable(remoteFileNode, SIZE_MAX, [=](int error) {
				if(error && error != ESPIPE)
					sharedState->error = error;
				else // Cache complete!
				{
					// Truncate the cache file
					if(fflush(remoteFileNode->m_localCache) != 0
					    || ftruncate(fileno(remoteFileNode->m_localCache), sharedState->value.st_size) == -1)
						sharedState->error = errno;
					else
					{
						remoteFileNode->m_cacheSize = remoteFileNode->m_stat.st_size = sharedState->value.st_size;
						that->markCacheDirty(remoteFileNode);
					}
				}

				markOperationCompleted(FUSE_SET_ATTR_SIZE);
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
				sharedState->error = ENOENT;
				markOperationCompleted(FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID);
			}
			else
			{
				QString newOwner = QString::fromUtf8(pw->pw_name),
				        newGroup = QString::fromUtf8(gr->gr_name);

				auto *job = KIO::chown(that->remoteUrl(node), newOwner, newGroup);
				that->connect(job, &KIO::SimpleJob::finished, [=] {
					if(job->error())
						sharedState->error = EIO;
					else
					{
						node->m_stat.st_uid = newUid;
						node->m_stat.st_gid = newGid;
					}

					markOperationCompleted(FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID);
				});
			}
		}

		if(to_set & (FUSE_SET_ATTR_MODE))
		{
			auto newMode = attr->st_mode & ~S_IFMT;
			auto *job = KIO::chmod(that->remoteUrl(node), newMode);
			that->connect(job, &KIO::SimpleJob::finished, [=] {
				if(job->error())
					sharedState->error = EIO;
				else
					node->m_stat.st_mode = (node->m_stat.st_mode & S_IFMT) | newMode;

				markOperationCompleted(FUSE_SET_ATTR_MODE);
			});
		}

		if(to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW))
		{
			if(to_set & FUSE_SET_ATTR_MTIME_NOW)
				sharedState->value.st_mtim = tsNow;

			auto time = QDateTime::fromMSecsSinceEpoch(sharedState->value.st_mtim.tv_sec * 1000
			                                           + sharedState->value.st_mtim.tv_nsec / 1000000);
			auto *job = KIO::setModificationTime(that->remoteUrl(node), time);
			that->connect(job, &KIO::SimpleJob::finished, [=] {
				if(job->error())
					sharedState->error = EIO;
				else // This is not quite correct, as KIO rounded the value down to a second
					node->m_stat.st_mtim = sharedState->value.st_mtim;

				markOperationCompleted(FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW);
			});
		}
	}
	}
}

void KIOFuseVFS::readlink(fuse_req_t req, fuse_ino_t ino)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
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

	fuse_reply_readlink(req, std::dynamic_pointer_cast<KIOFuseSymLinkNode>(node)->m_target.toUtf8().data());
}

void KIOFuseVFS::mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	Q_UNUSED(rdev);

	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto remote = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(node);
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

	auto url = that->remoteUrl(node);
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	auto *job = KIO::put(url, mode & ~S_IFMT);
	// Not connecting to the dataReq signal at all results in an empty file
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->mountUrl(url, [=](auto node, int error) {
			if(error)
				fuse_reply_err(req, error);
			else
				that->replyEntry(req, node);
		});
	});
}

void KIOFuseVFS::mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto remote = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(node);
	if(!remote)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto url = that->remoteUrl(node);
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	auto *job = KIO::mkdir(url, mode & ~S_IFMT);
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->mountUrl(url, [=](auto node, int error) {
			if(error)
				fuse_reply_err(req, error);
			else
				that->replyEntry(req, node);
		});
	});
}

void KIOFuseVFS::unlinkHelper(fuse_req_t req, fuse_ino_t parent, const char *name, bool isDirectory)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto parentNode = that->nodeForIno(parent);
	if(!parentNode)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	// Make sure the to-be deleted node is in a remote dir
	if(!std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(parentNode))
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto node = that->nodeByName(parentNode, QString::fromUtf8(name));
	if(!node)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	auto dirNode = std::dynamic_pointer_cast<KIOFuseDirNode>(node);

	if(!isDirectory && dirNode != nullptr)
	{
		fuse_reply_err(req, EISDIR);
		return;
	}

	if(isDirectory && dirNode == nullptr)
	{
		fuse_reply_err(req, ENOTDIR);
		return;
	}
	else if(dirNode	&& dirNode->m_childrenInos.size() != 0)
	{
		// If node is a dir, it must be empty
		fuse_reply_err(req, ENOTEMPTY);
		return;
	}

	auto *job = KIO::del(that->remoteUrl(node));
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->markNodeDeleted(node);
		fuse_reply_err(req, 0);
	});
}

void KIOFuseVFS::unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	unlinkHelper(req, parent, name, false);
}

void KIOFuseVFS::rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	unlinkHelper(req, parent, name, true);
}

void KIOFuseVFS::symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(parent);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto remote = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(node);
	if(!remote)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto url = that->remoteUrl(node);
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	auto *job = KIO::symlink(QString::fromUtf8(link), url);
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, EIO);
			return;
		}

		that->mountUrl(url, [=](auto node, int error) {
			if(error)
				fuse_reply_err(req, error);
			else
				that->replyEntry(req, node);
		});
	});
}

void KIOFuseVFS::open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	if(ino == KIOFuseIno::Control)
		fi->direct_io = true; // Necessary to get each command directly

	node->m_openCount += 1;

	fuse_reply_open(req, fi);
}

void KIOFuseVFS::rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	if(flags & ~(RENAME_NOREPLACE))
	{
		// RENAME_EXCHANGE could be emulated locally, but not with the same guarantees
		fuse_reply_err(req, EOPNOTSUPP);
		return;
	}

	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto parentNode = that->nodeForIno(parent), newParentNode = that->nodeForIno(newparent);
	if(!parentNode || !newParentNode)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto remoteParent = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(parentNode),
	     remoteNewParent = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(newParentNode);
	if(!remoteParent || !remoteNewParent)
	{
		fuse_reply_err(req, EINVAL);
		return;
	}

	auto node = that->nodeByName(remoteParent, QString::fromUtf8(name));
	if(!node)
	{
		fuse_reply_err(req, ENOENT);
		return;
	}

	QString newNameStr = QString::fromUtf8(newname);

	auto replacedNode = that->nodeByName(remoteNewParent, newNameStr);

	// Ensure that if node is a directory, replacedNode either does not exist or is an empty directory.
	if(std::dynamic_pointer_cast<KIOFuseDirNode>(node) && replacedNode)
	{
		auto replacedDir = std::dynamic_pointer_cast<KIOFuseDirNode>(replacedNode);
		if(!replacedDir)
		{
			fuse_reply_err(req, ENOTDIR);
			return;
		}
		if(replacedDir && replacedDir->m_childrenInos.size() != 0)
		{
			fuse_reply_err(req, ENOTEMPTY);
			return;
		}
	}

	auto url = that->remoteUrl(remoteParent),
	     newUrl = that->remoteUrl(remoteNewParent);
	url.setPath(url.path() + QLatin1Char('/') + QString::fromUtf8(name));
	newUrl.setPath(newUrl.path() + QLatin1Char('/') + newNameStr);

	auto *job = KIO::rename(url, newUrl, (flags & RENAME_NOREPLACE) ? KIO::DefaultFlags : KIO::Overwrite);
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
			fuse_reply_err(req, EIO);
		else
		{
			if(replacedNode)
				that->markNodeDeleted(replacedNode);

			that->reparentNode(node, newParentNode->m_stat.st_ino);
			node->m_nodeName = newNameStr;

			fuse_reply_err(req, 0);
		}
	});
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
	auto node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto dirNode = std::dynamic_pointer_cast<KIOFuseDirNode>(node);

	if(!dirNode)
	{
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	that->awaitChildrenComplete(dirNode, [=](int error){
		if(error)
		{
			fuse_reply_err(req, error);
			return;
		}

		std::vector<char> dirbuf;
		appendDirentry(dirbuf, req, ".", &node->m_stat);

		auto parentNode = that->nodeForIno(node->m_parentIno);
		if(!parentNode)
			parentNode = that->nodeForIno(KIOFuseIno::Root);
		if(parentNode)
			appendDirentry(dirbuf, req, "..", &parentNode->m_stat);

		for(auto ino : dirNode->m_childrenInos)
		{
			auto child = that->nodeForIno(ino);
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
	auto node = that->nodeForIno(ino);
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
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(node);
		that->awaitBytesAvailable(remoteNode, off + size, [=](int error) {
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
		fuse_reply_err(req, EPERM);
		break;
	}
}

void KIOFuseVFS::write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, fuse_file_info *fi)
{
	Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
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
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(node);
		that->awaitBytesAvailable(remoteNode, off + size, [=](int error) {
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
			that->markCacheDirty(remoteNode);

			fuse_reply_write(req, data.size());
		});
	}
	}
}

void KIOFuseVFS::flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	// This is called on each close of a FD, so it might be a bit overzealous
	// to do writeback here. I can't think of a better alternative though -
	// doing it only on fsync and the final forget seems like a bit too late.

	return KIOFuseVFS::fsync(req, ino, 1, fi);
}

void KIOFuseVFS::release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi)
{
	Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	node->m_openCount -= 1;

	fuse_reply_err(req, 0); // Ignored anyway

	auto remoteFileNode = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(node);
	if(node->m_openCount || !remoteFileNode || !remoteFileNode->m_localCache)
		return; // Nothing to do

	// When the cache is not dirty, remove the cache file.
	that->awaitNodeFlushed(remoteFileNode, [=](int error) {
		if(error != 0 || node->m_openCount != 0)
			return; // Better not remove the cache
		if(remoteFileNode->m_localCache == nullptr)
			return; // Already removed (happens if the file was reopened and closed while flushing)
		if(!remoteFileNode->cacheIsComplete())
			return; // Currently filling

		if(remoteFileNode->m_cacheDirty || remoteFileNode->m_flushRunning)
		{
			qWarning(KIOFUSE_LOG) << "Node turned dirty in flush callback";
			return;
		}

		qDebug(KIOFUSE_LOG) << "Removing cache of" << remoteFileNode->m_nodeName;
		fclose(remoteFileNode->m_localCache);
		remoteFileNode->m_cacheSize = 0;
		remoteFileNode->m_localCache = nullptr;
		remoteFileNode->m_cacheComplete = false;
	});
}

void KIOFuseVFS::fsync(fuse_req_t req, fuse_ino_t ino, int datasync, fuse_file_info *fi)
{
	Q_UNUSED(datasync); Q_UNUSED(fi);
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
	if(!node)
	{
		fuse_reply_err(req, EIO);
		return;
	}

	auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteFileNode>(node);
	if(!remoteNode)
	{
		fuse_reply_err(req, 0);
		return;
	}

	that->awaitNodeFlushed(remoteNode, [=](int error) {
		fuse_reply_err(req, error);
	});
}

std::shared_ptr<KIOFuseNode> KIOFuseVFS::nodeByName(const std::shared_ptr<KIOFuseNode> &parent, const QString name) const
{
	for(auto ino : std::dynamic_pointer_cast<const KIOFuseDirNode>(parent)->m_childrenInos)
	{
		auto child = nodeForIno(ino);
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
	auto parentNode = that->nodeForIno(parent);
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
		return that->replyEntry(req, child);

	// Not found - try again
	that->awaitChildrenComplete(std::dynamic_pointer_cast<KIOFuseDirNode>(parentNode), [=](int error) {
		if(error)
			fuse_reply_err(req, error);
		else
			that->replyEntry(req, that->nodeByName(parentNode, nodeName));
	});
}

void KIOFuseVFS::forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	auto node = that->nodeForIno(ino);
	if(node)
		that->decrementLookupCount(node, nlookup);

	fuse_reply_none(req);
}

std::shared_ptr<KIOFuseNode> KIOFuseVFS::nodeForIno(const fuse_ino_t ino) const
{
	auto it = m_nodes.find(ino);
	if(it == m_nodes.end())
		return nullptr;

	return it->second;
}

void KIOFuseVFS::reparentNode(const std::shared_ptr<KIOFuseNode> &node, fuse_ino_t newParentIno)
{
	if(node->m_parentIno == newParentIno)
		return;

	if(node->m_parentIno != KIOFuseIno::Invalid)
	{
		// Remove from old parent's children list
		if(auto parentDir = std::dynamic_pointer_cast<KIOFuseDirNode>(nodeForIno(node->m_parentIno)))
		{
			auto &childrenList = parentDir->m_childrenInos;
			auto it = std::find(begin(childrenList), end(childrenList), node->m_stat.st_ino);
			if(it != childrenList.end())
				childrenList.erase(it);
			else
				qWarning(KIOFUSE_LOG) << "Tried to reparent node with broken parent link";
		}
		else
			qWarning(KIOFUSE_LOG) << "Tried to reparent node with invalid parent";
	}

	node->m_parentIno = newParentIno;

	if(node->m_parentIno != KIOFuseIno::Invalid)
	{
		// Add to new parent's children list
		if(auto parentDir = std::dynamic_pointer_cast<KIOFuseDirNode>(nodeForIno(node->m_parentIno)))
			parentDir->m_childrenInos.push_back(node->m_stat.st_ino);
		else
			qWarning(KIOFUSE_LOG) << "Tried to insert node with invalid parent";
	}
}

fuse_ino_t KIOFuseVFS::insertNode(const std::shared_ptr<KIOFuseNode> &node, fuse_ino_t ino)
{
	if(ino == KIOFuseIno::Invalid)
	{
		// Allocate a free inode number
		while(ino == KIOFuseIno::Invalid || m_nodes.find(ino) != m_nodes.end())
			ino++;

		m_nextIno = ino + 1;
	}

	m_nodes[ino] = node;

	// Adjust internal ino
	node->m_stat.st_ino = ino;

	if(node->m_parentIno != KIOFuseIno::Invalid)
	{
		// Add to parent's child
		if(auto parentDir = std::dynamic_pointer_cast<KIOFuseDirNode>(nodeForIno(node->m_parentIno)))
			parentDir->m_childrenInos.push_back(ino);
		else
			qWarning(KIOFUSE_LOG) << "Tried to insert node with invalid parent";
	}

	return ino;
}

QUrl KIOFuseVFS::remoteUrl(const std::shared_ptr<const KIOFuseNode> &node) const
{
	// Special handling for KIOFuseRemoteFileNode
	if(auto remoteFileNode = std::dynamic_pointer_cast<const KIOFuseRemoteFileNode>(node))
	{
		if(!remoteFileNode->m_overrideUrl.isEmpty())
			return remoteFileNode->m_overrideUrl;
	}

	QStringList path;
	for(const KIOFuseNode *currentNode = node.get(); currentNode != nullptr; currentNode = nodeForIno(currentNode->m_parentIno).get())
	{
		auto remoteDirNode = dynamic_cast<const KIOFuseRemoteDirNode*>(currentNode);
		if(remoteDirNode && !remoteDirNode->m_overrideUrl.isEmpty())
		{
			// Origin found - add path and return
			path.prepend({}); // Add a leading slash if necessary
			QUrl url = remoteDirNode->m_overrideUrl;
			url.setPath(url.path() + path.join(QLatin1Char('/')), QUrl::DecodedMode);
			return url;
		}

		path.prepend(currentNode->m_nodeName);
	}

	// No origin found until the root - return an invalid URL
	return {};
}

QString KIOFuseVFS::virtualPath(const std::shared_ptr<KIOFuseNode> &node) const
{
	QStringList path;
	for(const KIOFuseNode *currentNode = node.get(); currentNode != nullptr; currentNode = nodeForIno(currentNode->m_parentIno).get())
		path.prepend(currentNode->m_nodeName);

	return path.join(QLatin1Char('/'));
}

void KIOFuseVFS::fillStatForFile(struct stat &attr)
{
	static uid_t uid = getuid();
	static gid_t gid = getgid();

	attr.st_nlink = 1;
	attr.st_mode = S_IFREG | 0755;
	attr.st_uid = uid;
	attr.st_gid = gid;
	attr.st_size = 0;
	attr.st_blksize = 512;
	// This is set to match st_size by replyAttr
	attr.st_blocks = 0;

	clock_gettime(CLOCK_REALTIME, &attr.st_atim);
	attr.st_mtim = attr.st_atim;
	attr.st_ctim = attr.st_atim;
}

void KIOFuseVFS::incrementLookupCount(const std::shared_ptr<KIOFuseNode> &node, uint64_t delta)
{
	if(node->m_lookupCount + delta < node->m_lookupCount)
		qWarning(KIOFUSE_LOG) << "Lookup count overflow!";
	else
		node->m_lookupCount += delta;
}

void KIOFuseVFS::decrementLookupCount(const std::shared_ptr<KIOFuseNode> node, uint64_t delta)
{
	if(node->m_lookupCount < delta)
		qWarning(KIOFUSE_LOG) << "Tried to set lookup count negative!";
	else
		node->m_lookupCount -= delta;

	if(node->m_parentIno == KIOFuseIno::DeletedRoot && node->m_lookupCount == 0)
	{
		// Delete the node
		m_dirtyNodes.extract(node->m_stat.st_ino);
		reparentNode(node, KIOFuseIno::DeletedRoot);
		m_nodes.erase(m_nodes.find(node->m_stat.st_ino));
	}
}

void KIOFuseVFS::markNodeDeleted(const std::shared_ptr<KIOFuseNode> &node)
{	
	reparentNode(node, KIOFuseIno::DeletedRoot);
	decrementLookupCount(node, 0); // Trigger reevaluation
}

void KIOFuseVFS::replyAttr(fuse_req_t req, std::shared_ptr<KIOFuseNode> node)
{
	// Set st_blocks accordingly
	node->m_stat.st_blocks = (node->m_stat.st_size + node->m_stat.st_blksize - 1) / node->m_stat.st_blksize;

	// TODO: Validity timeout?
	fuse_reply_attr(req, &node->m_stat, 1);
}

void KIOFuseVFS::replyEntry(fuse_req_t req, std::shared_ptr<KIOFuseNode> node)
{
	// Zero means invalid entry. Compared to an ENOENT reply, the kernel can cache this.
	struct fuse_entry_param entry {};

	if(node)
	{
		incrementLookupCount(node);

		entry.ino = node->m_stat.st_ino;
		entry.attr_timeout = 1.0;
		entry.entry_timeout = 1.0;
		entry.attr = node->m_stat;
	}

	fuse_reply_entry(req, &entry);
}

void KIOFuseVFS::sendNotifyInvalEntry(std::shared_ptr<KIOFuseNode> node)
{
	auto name = node->m_nodeName.toUtf8();
	fuse_lowlevel_notify_inval_entry(m_fuseSession, node->m_parentIno, name.data(), name.size());
}

std::shared_ptr<KIOFuseNode> KIOFuseVFS::createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno, QString nameOverride)
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
			auto ret = std::make_shared<KIOFuseSymLinkNode>(parentIno, name, attr);
			ret->m_target = target;
			ret->m_stat.st_size = ret->m_target.toUtf8().length();
			return ret;
		}
		else if(entry.isLink())
			return nullptr; // Does this even happen?
		else if(entry.isDir())
			return nullptr; // Maybe create a mountpoint (remote dir with override URL) here?
		else // Regular file pointing to URL
		{
			attr.st_mode |= S_IFREG;
			auto ret = std::make_shared<KIOFuseRemoteFileNode>(parentIno, name, attr);
			ret->m_overrideUrl = QUrl{entry.stringValue(KIO::UDSEntry::UDS_URL)};
			return ret;
		}
	}
	else if(entry.isLink())	// Check for link first as isDir can also be a link
	{
		attr.st_mode |= S_IFLNK;
		auto ret = std::make_shared<KIOFuseSymLinkNode>(parentIno, name, attr);
		ret->m_target = entry.stringValue(KIO::UDSEntry::UDS_LINK_DEST);
		attr.st_size = ret->m_target.size();
		return ret;
	}
	else if(entry.isDir())
	{
		attr.st_mode |= S_IFDIR;
		return std::make_shared<KIOFuseRemoteDirNode>(parentIno, name, attr);
	}
	else // it's a regular file
	{
		attr.st_mode |= S_IFREG;
		return std::make_shared<KIOFuseRemoteFileNode>(parentIno, name, attr);
	}
}

void KIOFuseVFS::awaitBytesAvailable(const std::shared_ptr<KIOFuseRemoteFileNode> &node, size_t bytes, std::function<void(int error)> callback)
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
		qDebug(KIOFUSE_LOG) << "Fetching cache for" << node->m_nodeName;
		auto *job = KIO::get(remoteUrl(node));
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
				// It's possible that the cache was written to meanwhile - that's bad.
				// TODO: Is it possible to recover?
				node->m_cacheDirty = false;

				fclose(node->m_localCache);
				node->m_cacheSize = false;
				node->m_cacheComplete = false;
				node->m_localCache = nullptr;
				emit node->localCacheChanged(EIO);
			}
			else
			{
				// Might be different from the attr size meanwhile, use the more recent value.
				// This also ensures that the cache is seen as complete.
				node->m_stat.st_size = node->m_cacheSize;
				node->m_cacheComplete = true;
				emit node->localCacheChanged(0);
			}
		});
	}

	// Using a unique_ptr here to let the lambda disconnect the connection itself
	auto connection = std::make_unique<QMetaObject::Connection>();
	auto &conn = *connection;
	conn = connect(node.get(), &KIOFuseRemoteFileNode::localCacheChanged,
	               [=, connection = std::move(connection)](int error) {
		if(error)
		{
			callback(error);
			node->disconnect(*connection);
		}
		else if(node->m_cacheSize >= bytes) // Requested data available
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
		// else continue waiting until the above happens
	}
	);
}

void KIOFuseVFS::awaitChildrenComplete(const std::shared_ptr<KIOFuseDirNode> &node, std::function<void (int)> callback)
{
	auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(node);
	if(!remoteNode)
		return callback(0); // Not a remote node

	if(remoteNode->m_childrenComplete)
		return callback(0);

	if(!remoteNode->m_childrenRequested)
	{
		// List the remote dir
		auto *job = KIO::listDir(remoteUrl(remoteNode));
		connect(job, &KIO::ListJob::entries, [=](auto *job, const KIO::UDSEntryList &entries) {
			Q_UNUSED(job);

			for(auto &entry : entries)
			{
				QString name = entry.stringValue(KIO::UDSEntry::UDS_NAME);

				// Ignore "." and ".."
				if(name == QStringLiteral(".") || name == QStringLiteral(".."))
				   continue;

				auto childrenNode = nodeByName(remoteNode, name);
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

				insertNode(childrenNode);
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
	conn = connect(remoteNode.get(), &KIOFuseRemoteDirNode::gotChildren,
	               [=, connection = std::move(connection)](int error) {
		callback(error);
		remoteNode->disconnect(*connection);
	}
	);
}

void KIOFuseVFS::mountUrl(QUrl url, std::function<void (const std::shared_ptr<KIOFuseNode> &, int)> callback)
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

		auto rootNode = nodeForIno(KIOFuseIno::Root);
		auto protocolNode = rootNode;

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

				protocolNode = std::make_shared<KIOFuseProtocolNode>(KIOFuseIno::Root, url.scheme(), attr);
				insertNode(protocolNode);
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

		auto originNode = nodeByName(protocolNode, originNodeName);

		if(!originNode)
		{
			struct stat attr = {};
			fillStatForFile(attr);
			attr.st_mode = S_IFDIR | 0755;

			auto newOriginNode = std::make_shared<KIOFuseRemoteDirNode>(protocolNode->m_stat.st_ino, originNodeName, attr);
			// Find out whether the base URL needs to start with a /
			if(url.path().startsWith(QLatin1Char('/')))
				(newOriginNode->m_overrideUrl = url).setPath(QStringLiteral("/"));
			else
				(newOriginNode->m_overrideUrl = url).setPath({});

			originNode = newOriginNode;
			insertNode(originNode);
		}
		else if(originNode->type() != KIOFuseNode::NodeType::RemoteDirNode)
			    return callback(nullptr, EIO);

		// Create all path components as directories
		auto pathNode = originNode;
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

			auto subdirNode = nodeByName(pathNode, pathElements[i]);
			if(!subdirNode)
			{
				struct stat attr = {};
				fillStatForFile(attr);
				attr.st_mode = S_IFDIR | 0755;

				subdirNode = std::make_shared<KIOFuseRemoteDirNode>(pathNode->m_stat.st_ino, pathElements[i], attr);
				insertNode(subdirNode);
			}

			pathNode = subdirNode;
		}

		// Finally create the last component
		auto finalNode = nodeByName(pathNode, pathElements.last());
		if(!finalNode)
		{
			// The remote name (statJob->statResult().stringValue(KIO::UDSEntry::UDS_NAME)) has to be
			// ignored as it can be different from the path. e.g. tar:/foo.tar/ is "/"
			finalNode = createNodeFromUDSEntry(statJob->statResult(), pathNode->m_stat.st_ino, pathElements.last());
			if(!finalNode)
				return callback(nullptr, EIO);

			insertNode(finalNode);
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
			return mountUrl(url, [=](auto node, int error) {
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

void KIOFuseVFS::markCacheDirty(const std::shared_ptr<KIOFuseRemoteFileNode> &node)
{
	node->m_cacheDirty = true;
	m_dirtyNodes.insert(node->m_stat.st_ino);
}

void KIOFuseVFS::awaitNodeFlushed(const std::shared_ptr<KIOFuseRemoteFileNode> &node, std::function<void (int)> callback)
{
	if(!node->m_cacheDirty && !node->m_flushRunning)
		return callback(0); // Nothing to flush/wait for

	if(node->m_parentIno == KIOFuseIno::DeletedRoot)
	{
		// Important: This is before marking it as flushed as it can be linked back.
		qDebug(KIOFUSE_LOG) << "Not flushing unlinked node" << node->m_nodeName;
		return callback(0);
	}

	// Don't send incomplete data
	if(!node->cacheIsComplete())
	{
		qDebug(KIOFUSE_LOG) << "Deferring flushing of node" << node->m_nodeName << "until cache complete";
		return awaitBytesAvailable(node, SIZE_MAX, [=](int error) {
			if(error)
				callback(error);
			else
				awaitNodeFlushed(node, callback);
		});
	}

	if(!node->m_flushRunning)
	{
		qDebug(KIOFUSE_LOG) << "Flushing node" << node->m_nodeName;

		// Clear the flag now to not lose any writes that happen while sending data
		node->m_cacheDirty = false;
		node->m_flushRunning = true;

		auto *job = KIO::put(remoteUrl(node), node->m_stat.st_mode & ~S_IFMT, KIO::Overwrite);
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
			node->m_flushRunning = false;

			if(job->error())
			{
				qWarning(KIOFUSE_LOG) << "Failed to send data:" << job->errorString();
				markCacheDirty(node); // Try again
				emit node->cacheFlushed(EIO);
				return;
			}

			if(!node->m_cacheDirty)
			{
				// Nobody wrote to the cache while sending data
				m_dirtyNodes.extract(node->m_stat.st_ino);
				emit node->cacheFlushed(0);
			}
			else
				awaitNodeFlushed(node, [](int){});
		});
	}

	// Using a unique_ptr here to let the lambda disconnect the connection itself
	auto connection = std::make_unique<QMetaObject::Connection>();
	auto &conn = *connection;
	conn = connect(node.get(), &KIOFuseRemoteFileNode::cacheFlushed,
	               [=, connection = std::move(connection)](int error) {
		callback(error);
		node->disconnect(*connection);
	}
	);
}
