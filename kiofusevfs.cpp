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

#include <qglobal.h>

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#ifdef Q_OS_LINUX
#include <linux/fs.h>
#include <sys/utsname.h>
#endif

#include <QDateTime>
#include <QDebug>
#include <QVersionNumber>

#include <KIO/ListJob>
#include <KIO/MkdirJob>
#include <KIO/StatJob>
#include <KIO/TransferJob>
#include <KIO/DeleteJob>
#include <KIO/FileJob>
#include <KProtocolManager>

#include "debug.h"
#include "kiofusevfs.h"

// Flags that don't exist on FreeBSD; since these are used as
// bit(masks), setting them to 0 effectively means they're always unset.
#ifndef O_NOATIME
#define O_NOATIME 0
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 0
#endif

// The libfuse macros make this necessary
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"

struct KIOFuseVFS::FuseLLOps : public fuse_lowlevel_ops
{
	FuseLLOps()
	{
		init = &KIOFuseVFS::init;
		lookup = &KIOFuseVFS::lookup;
		forget = &KIOFuseVFS::forget;
		getattr = &KIOFuseVFS::getattr;
		setattr = &KIOFuseVFS::setattr;
		readlink = &KIOFuseVFS::readlink;
		mknod = &KIOFuseVFS::mknod;
		mkdir = &KIOFuseVFS::mkdir;
		unlink = &KIOFuseVFS::unlink;
		rmdir = &KIOFuseVFS::rmdir;
		symlink = &KIOFuseVFS::symlink;
		rename = &KIOFuseVFS::rename;
		open = &KIOFuseVFS::open;
		read = &KIOFuseVFS::read;
		write = &KIOFuseVFS::write;
		flush = &KIOFuseVFS::flush;
		release = &KIOFuseVFS::release;
		fsync = &KIOFuseVFS::fsync;
		readdir = &KIOFuseVFS::readdir;
	}
};

const struct KIOFuseVFS::FuseLLOps KIOFuseVFS::fuse_ll_ops;

/* Handles partial writes and EINTR.
 * Returns true only if count bytes were written successfully. */
static bool sane_write(int fd, const void *buf, size_t count)
{
	size_t bytes_left = count;
	const char *buf_left = (const char*)buf;
	while(bytes_left)
	{
		ssize_t step = write(fd, buf_left, bytes_left);
		if(step == -1)
		{
			if(errno == EINTR)
				continue;
			else
				return false;
		}
		else if(step == 0)
			return false;

		bytes_left -= step;
		buf_left += step;
	}

	return true;
}

/* Handles partial reads and EINTR.
 * Returns true only if count bytes were read successfully. */
static bool sane_read(int fd, void *buf, size_t count)
{
	size_t bytes_left = count;
	char *buf_left = (char*)buf;
	while(bytes_left)
	{
		ssize_t step = read(fd, buf_left, bytes_left);
		if(step == -1)
		{
			if(errno == EINTR)
				continue;
			else
				return false;
		}
		else if(step == 0)
			return false;

		bytes_left -= step;
		buf_left += step;
	}

	return true;
}

int KIOFuseVFS::signalFd[2];

KIOFuseVFS::KIOFuseVFS(QObject *parent)
    : QObject(parent)
{
	struct stat attr = {};
	fillStatForFile(attr);
	attr.st_mode = S_IFDIR | 0755;

	auto root = std::make_shared<KIOFuseRootNode>(KIOFuseIno::Invalid, QString(), attr);
	insertNode(root, KIOFuseIno::Root);
	incrementLookupCount(root, 1); // Implicitly referenced by mounting

	auto deletedRoot = std::make_shared<KIOFuseRootNode>(KIOFuseIno::Invalid, QString(), attr);
	insertNode(deletedRoot, KIOFuseIno::DeletedRoot);
}

KIOFuseVFS::~KIOFuseVFS()
{
	stop();
}

bool KIOFuseVFS::start(struct fuse_args &args, const QString& mountpoint)
{
	if(!isEnvironmentValid())
	   return false;

	stop();
	m_fuseSession = fuse_session_new(&args, &fuse_ll_ops, sizeof(fuse_ll_ops), this);

	if(!m_fuseSession)
		return false;

	if(!setupSignalHandlers()
	   || fuse_session_mount(m_fuseSession, mountpoint.toUtf8().data()) != 0)
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

		removeSignalHandlers();
		fuse_session_unmount(m_fuseSession);
		fuse_session_destroy(m_fuseSession);
		m_fuseSession = nullptr;
	}

	// Flush all dirty nodes
	QEventLoop loop;
	bool needEventLoop = false;

	for(auto it = m_dirtyNodes.begin(); it != m_dirtyNodes.end();)
	{
		auto node = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(nodeForIno(*it));

		++it; // Increment now as awaitNodeFlushed invalidates the iterator

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

void KIOFuseVFS::setUseFileJob(bool useFileJob)
{
	m_useFileJob = useFileJob;
}

void KIOFuseVFS::init(void *userdata, fuse_conn_info *conn)
{
	Q_UNUSED(userdata);

	conn->want &= ~FUSE_CAP_HANDLE_KILLPRIV; // Don't care about resetting setuid/setgid flags
	conn->want &= ~FUSE_CAP_ATOMIC_O_TRUNC; // Use setattr with st_size = 0 instead of open with O_TRUNC
	// Writeback caching needs fuse_notify calls for shared filesystems, but those are broken by design
	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
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
	case KIOFuseNode::NodeType::RemoteDirNode:
	case KIOFuseNode::NodeType::RemoteCacheBasedFileNode:
	case KIOFuseNode::NodeType::RemoteFileJobBasedFileNode:
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
		if((to_set & FUSE_SET_ATTR_SIZE) && remoteFileNode->type() == KIOFuseNode::NodeType::RemoteCacheBasedFileNode)
		{
			auto cacheBasedFileNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(remoteFileNode);
			// Can be done directly if the new size is zero (and there is no get going on).
			// This is an optimization to avoid fetching the entire file just to ignore its content.
			if(!cacheBasedFileNode->m_localCache && attr->st_size == 0)
			{
				// Just create an empty file
				cacheBasedFileNode->m_localCache = tmpfile();
				if(cacheBasedFileNode->m_localCache == nullptr)
				{
					fuse_reply_err(req, EIO);
					return;
				}

				cacheBasedFileNode->m_cacheComplete = true;
				cacheBasedFileNode->m_cacheSize = cacheBasedFileNode->m_stat.st_size = 0;
				cacheBasedFileNode->m_stat.st_mtim = cacheBasedFileNode->m_stat.st_ctim = tsNow;
				that->markCacheDirty(cacheBasedFileNode);

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
				}
				else
					replyAttr(req, node);
			}
		};

		if((to_set & FUSE_SET_ATTR_SIZE) && remoteFileNode->type() == KIOFuseNode::NodeType::RemoteCacheBasedFileNode)
		{
			auto cacheBasedFileNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(remoteFileNode);
			// Have to wait until the cache is complete to truncate.
			// Waiting until all bytes up to the truncation point are available won't work,
			// as the fetch function would just overwrite the cache.
			that->awaitCacheComplete(cacheBasedFileNode, [=] (int error) {
				if(error)
					sharedState->error = error;
				else // Cache complete!
				{
					// Truncate the cache file
					if(fflush(cacheBasedFileNode->m_localCache) != 0
					    || ftruncate(fileno(cacheBasedFileNode->m_localCache), sharedState->value.st_size) == -1)
						sharedState->error = errno;
					else
					{
						cacheBasedFileNode->m_cacheSize = cacheBasedFileNode->m_stat.st_size = sharedState->value.st_size;
						cacheBasedFileNode->m_stat.st_mtim = cacheBasedFileNode->m_stat.st_ctim = tsNow;
						that->markCacheDirty(cacheBasedFileNode);
					}
				}
				markOperationCompleted(FUSE_SET_ATTR_SIZE);
			});
		}
		else if ((to_set & FUSE_SET_ATTR_SIZE) && remoteFileNode->type() == KIOFuseNode::NodeType::RemoteFileJobBasedFileNode)
		{
			auto fileJobBasedFileNode = std::dynamic_pointer_cast<KIOFuseRemoteFileJobBasedFileNode>(remoteFileNode);
			auto *fileJob = KIO::open(that->remoteUrl(fileJobBasedFileNode), QIODevice::ReadWrite);
			connect(fileJob, &KIO::FileJob::result, [=] (auto *job) {
				// All errors come through this signal, so error-handling is done here
				if(job->error())
				{
					sharedState->error = kioErrorToFuseError(job->error());
					markOperationCompleted(FUSE_SET_ATTR_SIZE);
				}
			});
			connect(fileJob, &KIO::FileJob::open, [=] {
				fileJob->truncate(sharedState->value.st_size);
				connect(fileJob, &KIO::FileJob::truncated, [=] {
					fileJob->close();
					connect(fileJob, qOverload<KIO::Job*>(&KIO::FileJob::close), [=] {
						fileJobBasedFileNode->m_stat.st_size = sharedState->value.st_size;
						markOperationCompleted(FUSE_SET_ATTR_SIZE);
					});
				});
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
						sharedState->error = kioErrorToFuseError(job->error());
					else
					{
						node->m_stat.st_uid = newUid;
						node->m_stat.st_gid = newGid;
						node->m_stat.st_ctim = tsNow;
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
					sharedState->error = kioErrorToFuseError(job->error());
				else
				{
					node->m_stat.st_mode = (node->m_stat.st_mode & S_IFMT) | newMode;
					node->m_stat.st_ctim = tsNow;
				}
				
				markOperationCompleted(FUSE_SET_ATTR_MODE);
			});
		}

		if(to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW))
		{
			if(to_set & FUSE_SET_ATTR_MTIME_NOW)
				sharedState->value.st_mtim = tsNow;

			auto time = QDateTime::fromMSecsSinceEpoch(qint64(sharedState->value.st_mtim.tv_sec) * 1000
			                                           + sharedState->value.st_mtim.tv_nsec / 1000000);
			auto *job = KIO::setModificationTime(that->remoteUrl(node), time);
			that->connect(job, &KIO::SimpleJob::finished, [=] {
				if(job->error())
					sharedState->error = kioErrorToFuseError(job->error());
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
			fuse_reply_err(req, kioErrorToFuseError(job->error()));
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
			fuse_reply_err(req, kioErrorToFuseError(job->error()));
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
	else if(dirNode	&& !dirNode->m_childrenInos.empty())
	{
		// If node is a dir, it must be empty
		fuse_reply_err(req, ENOTEMPTY);
		return;
	}

	if(auto fileJobNode = std::dynamic_pointer_cast<KIOFuseRemoteFileJobBasedFileNode>(node))
	{
		// After deleting a file, the contents become inaccessible immediately,
		// so avoid creating nameless inodes. tmpfile() semantics aren't possible with FileJob.
		if(fileJobNode->m_openCount)
		{
			fuse_reply_err(req, EBUSY);
			return;
		}
	}

	auto *job = KIO::del(that->remoteUrl(node));
	that->connect(job, &KIO::SimpleJob::finished, [=] {
		if(job->error())
		{
			fuse_reply_err(req, kioErrorToFuseError(job->error()));
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
			fuse_reply_err(req, kioErrorToFuseError(job->error()));
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

	node->m_openCount += 1;

	if (!(fi->flags & O_NOATIME))
		clock_gettime(CLOCK_REALTIME, &node->m_stat.st_atim);

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
		if(replacedDir && !replacedDir->m_childrenInos.empty())
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
			fuse_reply_err(req, kioErrorToFuseError(job->error()));
		else
		{
			if(replacedNode)
				that->markNodeDeleted(replacedNode);

			that->reparentNode(node, newParentNode->m_stat.st_ino);
			node->m_nodeName = newNameStr;

			clock_gettime(CLOCK_REALTIME, &node->m_stat.st_ctim);
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
			fuse_reply_buf(req, dirbuf.data() + off, std::min(off_t(size), off_t(dirbuf.size()) - off));
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
	case KIOFuseNode::NodeType::RemoteCacheBasedFileNode:
	{
		qDebug(KIOFUSE_LOG) << "Reading" << size << "byte(s) at offset" << off << "of (cache-based) node" << node->m_nodeName;
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(node);
		that->awaitBytesAvailable(remoteNode, off + size, [=] (int error) {
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
					actualSize = std::min(remoteNode->m_cacheSize - off, off_t(size));
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
	case KIOFuseNode::NodeType::RemoteFileJobBasedFileNode:
	{
		qDebug(KIOFUSE_LOG) << "Reading" << size << "byte(s) at offset" << off << "of (FileJob-based) node" << node->m_nodeName;
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteFileJobBasedFileNode>(node);
		auto *fileJob = KIO::open(that->remoteUrl(remoteNode), QIODevice::ReadOnly);
		connect(fileJob, &KIO::FileJob::result, [=] (auto *job) {
			// All errors come through this signal, so error-handling is done here
			if(job->error())
				fuse_reply_err(req, kioErrorToFuseError(job->error()));
		});
		connect(fileJob, &KIO::FileJob::open, [=] {
			fileJob->seek(off);
			connect(fileJob, &KIO::FileJob::position, [=] (auto *job, KIO::filesize_t offset) {
				Q_UNUSED(job);
				if(off_t(offset) != off)
				{
					fileJob->close();
					fileJob->connect(fileJob, qOverload<KIO::Job*>(&KIO::FileJob::close), [=] {
						fuse_reply_err(req, EIO);
					});
					return;
				}
				auto actualSize = remoteNode->m_stat.st_size = fileJob->size();
				// Reading over the end
				if(off >= off_t(actualSize))
					actualSize = 0;
				else
					actualSize = std::min(off_t(actualSize) - off, off_t(size));
				fileJob->read(actualSize);
				QByteArray buffer;
				fileJob->connect(fileJob, &KIO::FileJob::data, [=] (auto *readJob, const QByteArray &data) mutable {
					Q_UNUSED(readJob);
					QByteArray truncatedData = data.left(actualSize);
					buffer.append(truncatedData);
					actualSize -= truncatedData.size();

					if(actualSize > 0)
					{
						// Keep reading until we get all the data we need.
						fileJob->read(actualSize);
						return;
					}
					fileJob->close();
					fileJob->connect(fileJob, qOverload<KIO::Job*>(&KIO::FileJob::close), [=] {
						fuse_reply_buf(req, buffer.constData(), buffer.size());
					});
				});
			});
		});
		break;
	}
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
	case KIOFuseNode::NodeType::RemoteCacheBasedFileNode:
	{
		qDebug(KIOFUSE_LOG) << "Writing" << size << "byte(s) at offset" << off << "of (cache-based) node" << node->m_nodeName;
		QByteArray data(buf, size); // Copy data
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(node);
		// fi lives on the caller's stack make a copy.
		auto cacheBasedWriteCallback = [=, fi_flags=fi->flags] (int error) {
			if(error && error != ESPIPE)
			{
				fuse_reply_err(req, error);
				return;
			}

			off_t offset = (fi_flags & O_APPEND) ? remoteNode->m_cacheSize : off;

			int cacheFd = fileno(remoteNode->m_localCache);
			if(lseek(cacheFd, offset, SEEK_SET) == -1
			   || !sane_write(cacheFd, data.data(), data.size()))
			{
				fuse_reply_err(req, errno);
				return;
			}

			remoteNode->m_cacheSize = std::max(remoteNode->m_cacheSize, off_t(offset + size));
			remoteNode->m_stat.st_size = remoteNode->m_cacheSize;
			// Update [cm] time as without writeback caching,
			// the kernel doesn't do this for us.
			clock_gettime(CLOCK_REALTIME, &remoteNode->m_stat.st_mtim);
			remoteNode->m_stat.st_ctim = remoteNode->m_stat.st_mtim;
			that->markCacheDirty(remoteNode);

			fuse_reply_write(req, data.size());
		};

		if(fi->flags & O_APPEND)
			// Wait for cache to be complete to ensure valid m_cacheSize
			that->awaitCacheComplete(remoteNode, cacheBasedWriteCallback);
		else
			that->awaitBytesAvailable(remoteNode, off + size, cacheBasedWriteCallback);
		break;
	}
	case KIOFuseNode::NodeType::RemoteFileJobBasedFileNode:
	{
		qDebug(KIOFUSE_LOG) << "Writing" << size << "byte(s) at offset" << off << "of (FileJob-based) node" << node->m_nodeName;
		QByteArray data(buf, size); // Copy data
		auto remoteNode = std::dynamic_pointer_cast<KIOFuseRemoteFileJobBasedFileNode>(node);
		auto *fileJob = KIO::open(that->remoteUrl(remoteNode), QIODevice::ReadWrite);
		connect(fileJob, &KIO::FileJob::result, [=] (auto *job) {
			// All errors come through this signal, so error-handling is done here
			if(job->error())
				fuse_reply_err(req, kioErrorToFuseError(job->error()));
		});
		connect(fileJob, &KIO::FileJob::open, [=, fi_flags=fi->flags] {
			off_t offset = (fi_flags & O_APPEND) ? fileJob->size() : off;
			fileJob->seek(offset);
			connect(fileJob, &KIO::FileJob::position, [=] (auto *job, KIO::filesize_t offset) {
				Q_UNUSED(job);
				if (off_t(offset) != off) {
					fileJob->close();
					fileJob->connect(fileJob, qOverload<KIO::Job*>(&KIO::FileJob::close), [=] {
						fuse_reply_err(req, EIO);
					});
					return;
				}
				// Limit write to avoid killing the slave.
				// @see https://phabricator.kde.org/D15448
				fileJob->write(data.left(0xFFFFFF));
				off_t bytesLeft = size;
				fileJob->connect(fileJob, &KIO::FileJob::written, [=] (auto *writeJob, KIO::filesize_t written) mutable {
					Q_UNUSED(writeJob);
					bytesLeft -= written;
					if (bytesLeft > 0)
					{
						// Keep writing until we write all the data we need.
						fileJob->write(data.mid(size - bytesLeft, 0xFFFFFF));
						return;
					}
					fileJob->close();
					fileJob->connect(fileJob, qOverload<KIO::Job*>(&KIO::FileJob::close), [=] {
						// Wait till we've flushed first...
						remoteNode->m_stat.st_size = std::max(off_t(offset + data.size()), remoteNode->m_stat.st_size);
						fuse_reply_write(req, data.size());
					});
				});
			});
		});
		break;
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

	auto remoteFileNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(node);
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
			if(remoteFileNode->m_parentIno == KIOFuseIno::DeletedRoot)
				return; // Closed a deleted dirty file, keep the cache as it could be reopened

			// Can't happen, but if it does, avoid data loss and potential crashing later by keeping
			// the cache.
			qWarning(KIOFUSE_LOG) << "Node" << remoteFileNode->m_nodeName << "turned dirty in flush callback";
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

	if(auto cacheBasedFileNode = std::dynamic_pointer_cast<KIOFuseRemoteCacheBasedFileNode>(node))
		that->awaitNodeFlushed(cacheBasedFileNode, [=](int error) {
			fuse_reply_err(req, error);
		});
	else
		fuse_reply_err(req, 0);
}

bool KIOFuseVFS::isEnvironmentValid()
{
	static_assert(sizeof(off_t) >= 8, "Please compile with -D_FILE_OFFSET_BITS=64 to allow working with large (>4GB) files");

#ifdef Q_OS_LINUX
	// On 32bit Linux before "fuse: fix writepages on 32bit", writes past 4GiB were silently discarded.
	// Technically this would have to check the kernel's bitness, but that's not easily possible.
	if(sizeof(size_t) != sizeof(off_t))
	{
		struct utsname uts;
		if(uname(&uts) != 0)
			return false;

		auto kernelversion = QVersionNumber::fromString(QLatin1String(uts.release));
		if(kernelversion < QVersionNumber(5, 2))
		{
			qCritical(KIOFUSE_LOG) << "You're running kio-fuse on an older 32-bit kernel, which can lead to data loss.\n"
			                          "Please use a newer one or make sure that the 'fuse: fix writepages on 32bit' commit "
			                          "is part of the kernel and then build kio-fuse with this check adjusted.\n"
			                          "If you don't know how to do that, please file a bug at your distro.";
			return false;
		}
	}
#endif

	return true;
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

	QUrl url = that->remoteUrl(parentNode);
	if(url.isEmpty())
	{
		// Directory not remote, so definitely does not exist
		fuse_reply_err(req, ENOENT);
		return;
	}

	// Not in the local tree, but remote - try again
	url.setPath(url.path() + QLatin1Char('/') + nodeName);
	that->mountUrl(url, [=](auto node, int error) {
		if(error && error != ENOENT)
			fuse_reply_err(req, error);
		else
			that->replyEntry(req, node);
	});
}

void KIOFuseVFS::forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
	if(auto node = that->nodeForIno(ino))
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

QUrl KIOFuseVFS::localPathToRemoteUrl(const QString& localPath) const
{
	auto node = nodeForIno(KIOFuseIno::Root);
	for (const auto &segment : localPath.split(QStringLiteral("/")))
	{
		 node = nodeByName(node, segment);
		 if(!node)
			 return {};
	}
	return remoteUrl(node);
}

QUrl KIOFuseVFS::sanitizeNullAuthority(QUrl url) const
{
	// Workaround to allow url with scheme "file"
	// to have a path that starts with "//"
	// Without this patch...
	// file: + //tmp = invalid URL
	// file:// + //tmp = file////tmp
	if(url.authority().isNull())
		url.setAuthority(QStringLiteral(""));
	return url;
}

QUrl KIOFuseVFS::remoteUrl(const std::shared_ptr<const KIOFuseNode> &node) const
{
	// Special handling for KIOFuseRemoteFileNode
	if(auto remoteFileNode = std::dynamic_pointer_cast<const KIOFuseRemoteFileNode>(node))
	{
		if(!remoteFileNode->m_overrideUrl.isEmpty())
			return sanitizeNullAuthority(remoteFileNode->m_overrideUrl);
	}

	QStringList path;
	for(const KIOFuseNode *currentNode = node.get(); currentNode != nullptr; currentNode = nodeForIno(currentNode->m_parentIno).get())
	{
		auto remoteDirNode = dynamic_cast<const KIOFuseRemoteDirNode*>(currentNode);
		if(remoteDirNode && !remoteDirNode->m_overrideUrl.isEmpty())
		{
			// Origin found - add path and return
			QUrl url = sanitizeNullAuthority(remoteDirNode->m_overrideUrl);
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
		reparentNode(node, KIOFuseIno::Invalid);
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
			std::shared_ptr<KIOFuseRemoteFileNode> ret = nullptr;
			const QUrl nodeUrl = QUrl{entry.stringValue(KIO::UDSEntry::UDS_URL)};
			if(m_useFileJob && KProtocolManager::supportsOpening(nodeUrl) && KProtocolManager::supportsTruncating(nodeUrl))
				ret = std::make_shared<KIOFuseRemoteFileJobBasedFileNode>(parentIno, name, attr);
			else
				ret = std::make_shared<KIOFuseRemoteCacheBasedFileNode>(parentIno, name, attr);
			ret->m_overrideUrl = nodeUrl;
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
		const QUrl nodeUrl = remoteUrl(nodeForIno(parentIno));
		if(m_useFileJob && KProtocolManager::supportsOpening(nodeUrl) && KProtocolManager::supportsTruncating(nodeUrl))
			return std::make_shared<KIOFuseRemoteFileJobBasedFileNode>(parentIno, name, attr);
		else
			return std::make_shared<KIOFuseRemoteCacheBasedFileNode>(parentIno, name, attr);
	}
}

void KIOFuseVFS::awaitBytesAvailable(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, off_t bytes, std::function<void(int error)> callback)
{
	if(bytes < 0)
	{
		qWarning(KIOFUSE_LOG) << "Negative size passed to awaitBytesAvailable";
		return callback(EINVAL);
	}

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
			// Nobody needs the data anymore? Drop the cache.
			if(node->m_openCount == 0 && !node->m_cacheDirty && !node->m_flushRunning)
			{
				// KJob::Quietly would break the cache in the result handler while
				// the error handler sets up the node state just right.
				job->kill(KJob::EmitResult);
				qDebug(KIOFUSE_LOG) << "Stopped filling the cache of" << node->m_nodeName;
				return;
			}

			int cacheFd = fileno(node->m_localCache);
			if(lseek(cacheFd, 0, SEEK_END) == -1
			   || !sane_write(cacheFd, data.data(), data.size()))
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
				node->m_cacheSize = 0;
				node->m_cacheComplete = false;
				node->m_localCache = nullptr;
				emit node->localCacheChanged(kioErrorToFuseError(job->error()));
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
	conn = connect(node.get(), &KIOFuseRemoteCacheBasedFileNode::localCacheChanged,
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

void KIOFuseVFS::awaitCacheComplete(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, std::function<void (int)> callback)
{
	return awaitBytesAvailable(node, std::numeric_limits<off_t>::max(), [callback](int error) {
		// ESPIPE == cache complete, but less than the requested size, which is expected.
		return callback(error == ESPIPE ? 0 : error);
	});
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
				emit remoteNode->gotChildren(kioErrorToFuseError(job->error()));
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
			callback(nullptr, kioErrorToFuseError(statJob->error()));
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
			newOriginNode->m_overrideUrl = makeOriginUrl(url);

			originNode = newOriginNode;
			insertNode(originNode);
		}
		else if(originNode->type() != KIOFuseNode::NodeType::RemoteDirNode)
			    return callback(nullptr, EIO);
		else // Allow the user to change the password
			std::dynamic_pointer_cast<KIOFuseRemoteDirNode>(originNode)->m_overrideUrl = makeOriginUrl(url);
		

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

QUrl KIOFuseVFS::makeOriginUrl(QUrl url)
{
	// Find out whether the base URL needs to start with a /
	if(url.path().startsWith(QLatin1Char('/')))
		url.setPath(QStringLiteral("/"));
	else
		url.setPath({});

	return url;
}

void KIOFuseVFS::markCacheDirty(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node)
{
	if(node->m_cacheDirty)
		return; // Already dirty, nothing to do

	node->m_cacheDirty = true;
	m_dirtyNodes.insert(node->m_stat.st_ino);
}

void KIOFuseVFS::awaitNodeFlushed(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, std::function<void (int)> callback)
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
		return awaitCacheComplete(node, [=](int error) {
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

		auto *job = KIO::put(remoteUrl(node), -1, KIO::Overwrite);
		job->setTotalSize(node->m_cacheSize);

		off_t bytesSent = 0; // Modified inside the lambda
		connect(job, &KIO::TransferJob::dataReq, [=](auto *job, QByteArray &data) mutable {
			Q_UNUSED(job);

			// Someone truncated the file?
			if(node->m_cacheSize <= bytesSent)
				return;

			// Somebody wrote to the cache whilst sending data.
			// Kill the job to save time and try again.
			// However, set a limit to how many times we do this consecutively.
			if(node->m_cacheDirty && node->m_numKilledJobs < 2 && job->percent() < 85)
			{
				job->kill(KJob::Quietly);
				node->m_numKilledJobs++;
				node->m_flushRunning = false;
				awaitNodeFlushed(node, [](int){});
				return;
			}

			off_t toSend = std::min(node->m_cacheSize - bytesSent, off_t(14*1024*1024ul)); // 14MiB max
			data.resize(toSend);

			// Read the cache file into the buffer
			int cacheFd = fileno(node->m_localCache);
			if(lseek(cacheFd, bytesSent, SEEK_SET) == -1
			   || !sane_read(cacheFd, data.data(), toSend))
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
				emit node->cacheFlushed(kioErrorToFuseError(job->error()));
				return;
			}

			if(!node->m_cacheDirty)
			{
				// Nobody wrote to the cache while sending data
				m_dirtyNodes.extract(node->m_stat.st_ino);
				node->m_numKilledJobs = 0;
				emit node->cacheFlushed(0);
			}
			else
				awaitNodeFlushed(node, [](int){});
		});
	}

	// Using a unique_ptr here to let the lambda disconnect the connection itself
	auto connection = std::make_unique<QMetaObject::Connection>();
	auto &conn = *connection;
	conn = connect(node.get(), &KIOFuseRemoteCacheBasedFileNode::cacheFlushed,
	               [=, connection = std::move(connection)](int error) {
		callback(error);
		node->disconnect(*connection);
	}
	);
}

bool KIOFuseVFS::setupSignalHandlers() 
{
	// Create required socketpair for custom signal handling
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, signalFd)) {
		return false;
	}
	m_signalNotifier = std::make_unique<QSocketNotifier>(signalFd[1], QSocketNotifier::Read, this);
	m_signalNotifier->connect(m_signalNotifier.get(), &QSocketNotifier::activated, this, &KIOFuseVFS::exitHandler);
	
	struct sigaction sig;

	sig.sa_handler = KIOFuseVFS::signalHandler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sig, 0))
		return false;
	if (sigaction(SIGTERM, &sig, 0))
		return false;
	if (sigaction(SIGINT, &sig, 0))
		return false;

	return true;
}

bool KIOFuseVFS::removeSignalHandlers() 
{
	m_signalNotifier.reset();
	::close(signalFd[0]);
	::close(signalFd[1]);

	struct sigaction sig;

	sig.sa_handler = SIG_DFL;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sig, 0))
		return false;
	if (sigaction(SIGTERM, &sig, 0))
		return false;
	if (sigaction(SIGINT, &sig, 0))
		return false;

	return true;
}

void KIOFuseVFS::exitHandler() 
{
	m_signalNotifier->setEnabled(false);
	int tmp;
	::read(signalFd[1], &tmp, sizeof(tmp));
	stop();
}

void KIOFuseVFS::signalHandler(int signal) 
{
	::write(signalFd[0], &signal, sizeof(signal));
}

int KIOFuseVFS::kioErrorToFuseError(const int kioError) {
	switch (kioError) {
		case 0                                     : return 0; // No error
		case KIO::ERR_CANNOT_OPEN_FOR_READING      : return EIO;
		case KIO::ERR_CANNOT_OPEN_FOR_WRITING      : return EIO;
		case KIO::ERR_CANNOT_LAUNCH_PROCESS        : return EPERM;
		case KIO::ERR_INTERNAL                     : return EPROTO;
		case KIO::ERR_MALFORMED_URL                : return EBADF;
		case KIO::ERR_UNSUPPORTED_PROTOCOL         : return ENOPROTOOPT;
		case KIO::ERR_NO_SOURCE_PROTOCOL           : return ENOPROTOOPT;
		case KIO::ERR_UNSUPPORTED_ACTION           : return ENOTTY;
		case KIO::ERR_IS_DIRECTORY                 : return EISDIR;
		case KIO::ERR_IS_FILE                      : return EEXIST;
		case KIO::ERR_DOES_NOT_EXIST               : return ENOENT;
		case KIO::ERR_FILE_ALREADY_EXIST           : return EEXIST;
		case KIO::ERR_DIR_ALREADY_EXIST            : return EEXIST;
		case KIO::ERR_UNKNOWN_HOST                 : return EHOSTUNREACH;
		case KIO::ERR_ACCESS_DENIED                : return EPERM;
		case KIO::ERR_WRITE_ACCESS_DENIED          : return EPERM;
		case KIO::ERR_CANNOT_ENTER_DIRECTORY       : return ENOENT;
		case KIO::ERR_PROTOCOL_IS_NOT_A_FILESYSTEM : return EPROTOTYPE;
		case KIO::ERR_CYCLIC_LINK                  : return ELOOP;
		case KIO::ERR_USER_CANCELED                : return ECANCELED;
		case KIO::ERR_CYCLIC_COPY                  : return ELOOP;
		case KIO::ERR_COULD_NOT_CREATE_SOCKET      : return ENOTCONN;
		case KIO::ERR_CANNOT_CONNECT               : return ENOTCONN;
		case KIO::ERR_CONNECTION_BROKEN            : return ENOTCONN;
		case KIO::ERR_NOT_FILTER_PROTOCOL          : return EPROTOTYPE;
		case KIO::ERR_CANNOT_MOUNT                 : return EIO;
		case KIO::ERR_CANNOT_READ                  : return EIO;
		case KIO::ERR_CANNOT_WRITE                 : return EIO;
		case KIO::ERR_CANNOT_BIND                  : return EPERM;
		case KIO::ERR_CANNOT_LISTEN                : return EPERM;
		case KIO::ERR_CANNOT_ACCEPT                : return EPERM;
		case KIO::ERR_CANNOT_LOGIN                 : return ECONNREFUSED;
		case KIO::ERR_CANNOT_STAT                  : return EIO;
		case KIO::ERR_CANNOT_CLOSEDIR              : return EIO;
		case KIO::ERR_CANNOT_MKDIR                 : return EIO;
		case KIO::ERR_CANNOT_RMDIR                 : return EIO;
		case KIO::ERR_CANNOT_RESUME                : return ECONNABORTED;
		case KIO::ERR_CANNOT_RENAME                : return EIO;
		case KIO::ERR_CANNOT_CHMOD                 : return EIO;
		case KIO::ERR_CANNOT_DELETE                : return EIO;
		case KIO::ERR_SLAVE_DIED                   : return EIO;
		case KIO::ERR_OUT_OF_MEMORY                : return ENOMEM;
		case KIO::ERR_UNKNOWN_PROXY_HOST           : return EHOSTUNREACH;
		case KIO::ERR_CANNOT_AUTHENTICATE          : return EACCES;
		case KIO::ERR_ABORTED                      : return ECONNABORTED;
		case KIO::ERR_INTERNAL_SERVER              : return EPROTO;
		case KIO::ERR_SERVER_TIMEOUT               : return ETIMEDOUT;
		case KIO::ERR_SERVICE_NOT_AVAILABLE        : return ENOPROTOOPT;
		case KIO::ERR_UNKNOWN                      : return ENOENT;
		case KIO::ERR_UNKNOWN_INTERRUPT            : return ENOENT;
		case KIO::ERR_CANNOT_DELETE_ORIGINAL       : return EIO;
		case KIO::ERR_CANNOT_DELETE_PARTIAL        : return EIO;
		case KIO::ERR_CANNOT_RENAME_ORIGINAL       : return EIO;
		case KIO::ERR_CANNOT_RENAME_PARTIAL        : return EIO;
		case KIO::ERR_NEED_PASSWD                  : return EACCES;
		case KIO::ERR_CANNOT_SYMLINK               : return EIO;
		case KIO::ERR_NO_CONTENT                   : return ENODATA;
		case KIO::ERR_DISK_FULL                    : return ENOMEM;
		case KIO::ERR_IDENTICAL_FILES              : return EEXIST;
		case KIO::ERR_SLAVE_DEFINED                : return EALREADY;
		case KIO::ERR_UPGRADE_REQUIRED             : return EPROTOTYPE;
		case KIO::ERR_POST_DENIED                  : return EACCES;
		case KIO::ERR_COULD_NOT_SEEK               : return EIO;
		case KIO::ERR_CANNOT_SETTIME               : return EIO;
		case KIO::ERR_CANNOT_CHOWN                 : return EIO;
		case KIO::ERR_POST_NO_SIZE                 : return EIO;
		case KIO::ERR_DROP_ON_ITSELF               : return EINVAL;
		case KIO::ERR_CANNOT_MOVE_INTO_ITSELF      : return EINVAL;
		case KIO::ERR_PASSWD_SERVER                : return EIO;
		case KIO::ERR_CANNOT_CREATE_SLAVE          : return EIO;
		case KIO::ERR_FILE_TOO_LARGE_FOR_FAT32     : return EFBIG;
		case KIO::ERR_OWNER_DIED                   : return EIO;
		default                                    : return EIO;
	}
}
