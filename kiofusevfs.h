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

#pragma once

#include <fuse_lowlevel.h>

#include <functional>
#include <memory>
#include <set>
#include <unordered_map>

#include <QEventLoopLocker>
#include <QObject>
#include <QSocketNotifier>

#include "kiofusenode.h"

// Forward declarations
namespace KIO { class UDSEntry; }

enum KIOFuseIno : fuse_ino_t {
	/** Not reserved by the kernel, so used as a marker. */
	Invalid = 0,
	/** Defined by the kernel */
	Root = 1,

	/** The inode number of the parent of deleted nodes. */
	DeletedRoot,
	/** The inode number of the _control file. */
	Control,

	/** Dynamic allocation by insertNode starts here. */
	DynamicStart,
};

class KIOFuseVFS : public QObject
{
	Q_OBJECT
public:
	explicit KIOFuseVFS(QObject *parent = nullptr);
	~KIOFuseVFS();

	/** Mounts the filesystem at mountpoint. Returns true on success. */
	bool start(fuse_args &args, const char *mountpoint);
	/** Umounts the filesystem (if necessary) and flushes dirty nodes. */
	void stop();

private Q_SLOTS:
	void fuseRequestPending();

private:
	// Functions used by fuse_lowlevel_ops
	static void init(void *userdata, struct fuse_conn_info *conn);
	static void lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
	static void forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
	static void getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi);
	static void readlink(fuse_req_t req, fuse_ino_t ino);
	static void mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
	static void mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
	static void unlinkHelper(fuse_req_t req, fuse_ino_t parent, const char *name, bool isDirectory=false);
	static void unlink(fuse_req_t req, fuse_ino_t parent, const char *name); // Just calls unlinkHelper
	static void rmdir(fuse_req_t req, fuse_ino_t parent, const char *name); // Just calls unlinkHelper
	static void symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);
	static void open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi);
	static void rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
	                   const char *newname, unsigned int flags);
	static void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                    struct fuse_file_info *fi);
	static void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                 struct fuse_file_info *fi);
	static void write(fuse_req_t req, fuse_ino_t ino, const char *buf,
	                  size_t size, off_t off, struct fuse_file_info *fi);
	static void flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);

	/** Returns a pointer to a child node of parent with m_nodeName == name or nullptr. */
	std::shared_ptr<KIOFuseNode> nodeByName(const std::shared_ptr<KIOFuseNode> &parent, const QString name) const;
	/** Returns a pointer to the KIOFuseNode with inode number ino or nullptr. */
	std::shared_ptr<KIOFuseNode> nodeForIno(const fuse_ino_t ino) const;
	/** Removes the node from the old parent's children list (if any) and adds it to the new parent's list.*/
	void reparentNode(const std::shared_ptr<KIOFuseNode> &node, fuse_ino_t newParentIno);
	/** Allocates a new inode number if not given, adds node into m_nodes
	  * and adds it to the node parent's children list. */
	fuse_ino_t insertNode(const std::shared_ptr<KIOFuseNode> &node, fuse_ino_t ino=KIOFuseIno::Invalid);

	/** Returns the full url upwards until a OriginNode is hit.
	  * If no OriginNode is found, an empty QUrl is returned. */
	QUrl remoteUrl(const std::shared_ptr<const KIOFuseNode> &node) const;
	/** Returns the path upwards until a root node. */
	QString virtualPath(const std::shared_ptr<KIOFuseNode> &node) const;

	/** Fills a (previously zeroed out) struct stat with minimal information about a fake file. */
	void fillStatForFile(struct stat &attr);
	/** Increments the lookup count of node by delta. */
	void incrementLookupCount(const std::shared_ptr<KIOFuseNode> &node, uint64_t delta=1);
	/** Adjusts the lookup count and deletes the node if it is now zero and a child of DeletedRoot. */
	void decrementLookupCount(const std::shared_ptr<KIOFuseNode> node, uint64_t delta=1);
	/** Depending on the lookup count, it makes the node a child of DeletedRoot or deletes it directly. */
	void markNodeDeleted(const std::shared_ptr<KIOFuseNode> &node);
	/** Creates a new node with the matching type and fills m_stat fields. */
	std::shared_ptr<KIOFuseNode> createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno, QString nameOverride={});

	/** Sends the node's attributes with fuse_reply_attr. */
	static void replyAttr(fuse_req_t req, std::shared_ptr<KIOFuseNode> node);

	/** Invokes callback on error or when the bytes are available for reading/writing.
	  * If the file is smaller than bytes, it sets error = ESPIPE. */
	void awaitBytesAvailable(const std::shared_ptr<KIOFuseRemoteFileNode> &node, size_t bytes, std::function<void(int error)> callback);
	/** Invokes callback on error or when all children nodes are available */
	void awaitChildrenComplete(const std::shared_ptr<KIOFuseDirNode> &node, std::function<void(int error)> callback);
	/** Marks a node's cache as dirty and add it to m_dirtyNodes. */
	void markCacheDirty(const std::shared_ptr<KIOFuseRemoteFileNode> &node);
	/** Calls the callback once the cache is not dirty anymore (no cache counts as clean as well).
	  * If writes happen while a flush is sending data, a flush will be retriggered. */
	void awaitNodeFlushed(const std::shared_ptr<KIOFuseRemoteFileNode> &node, std::function<void(int error)> callback);

	/** Runs KIO::stat on url and adds a node to the tree if successful. Calls the callback at the end. */
	void mountUrl(QUrl url, std::function<void(const std::shared_ptr<KIOFuseNode>&, int)> callback);
	/** Handles the _control command in cmd asynchronously and call callback upon completion or failure. */
	void handleControlCommand(QString cmd, std::function<void(int error)> callback);

	/** Prevent the Application from quitting. */
	std::unique_ptr<QEventLoopLocker> m_eventLoopLocker;

	/** Struct of implemented fuse operations. */
	static const struct fuse_lowlevel_ops fuse_ll_ops;

	/** Fuse bookkeeping. */
	struct fuse_session *m_fuseSession = nullptr;
	/** Fuse bookkeeping. */
	std::unique_ptr<QSocketNotifier> m_fuseNotifier;

	/** Used by insertNode for accelerating the search for the next free inode number. */
	fuse_ino_t m_nextIno = KIOFuseIno::DynamicStart;
	/** Map of all known inode numbers to KIOFuseNodes. */
	std::unordered_map<fuse_ino_t, std::shared_ptr<KIOFuseNode>> m_nodes;
	/** Set of all nodes with a dirty cache. */
	std::set<fuse_ino_t> m_dirtyNodes;
};
