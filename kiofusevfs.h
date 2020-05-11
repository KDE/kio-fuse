/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
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
	bool start(fuse_args &args, const QString& mountpoint);
	/** Umounts the filesystem (if necessary) and flushes dirty nodes. */
	void stop();
	/** Designates whether KIOFuse should perform FileJob-based (KIO::open) I/O where possible. */
	void setUseFileJob(bool useFileJob);
	/** Runs KIO::stat on url and adds a node to the tree if successful. Calls the callback at the end. */
	void mountUrl(QUrl url, std::function<void(const std::shared_ptr<KIOFuseNode>&, int)> callback);
	/** Converts a local path into a remote URL if it is mounted within the VFS */
	QUrl localPathToRemoteUrl(const QString &localPath) const;
	/** Returns the path upwards until a root node. */
	QString virtualPath(const std::shared_ptr<KIOFuseNode> &node) const;

private Q_SLOTS:
	void fuseRequestPending();
	void exitHandler();

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

	/** Does some checks of the environment. Returns false if a critical issue was found. */
	bool isEnvironmentValid();

	/** Setups signal handlers. Returns true if successful, false otherwise **/
	bool setupSignalHandlers();
	/** Reverts to default signal handlers. Returns true if successful, false otherwise. **/
	bool removeSignalHandlers();
	/** Notifies m_signalNotifier of a signal **/
	static void signalHandler(int signal);

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

	/** Fills a (previously zeroed out) struct stat with minimal information about a fake file. */
	void fillStatForFile(struct stat &attr);
	/** Increments the lookup count of node by delta. */
	void incrementLookupCount(const std::shared_ptr<KIOFuseNode> &node, uint64_t delta=1);
	/** Adjusts the lookup count and deletes the node if it is now zero and a child of DeletedRoot. */
	void decrementLookupCount(const std::shared_ptr<KIOFuseNode> node, uint64_t delta=1);
	/** Depending on the lookup count, it makes the node a child of DeletedRoot or deletes it directly. */
	void markNodeDeleted(const std::shared_ptr<KIOFuseNode> &node);
	/** Creates a new node with the matching type and fills m_stat fields. */
	std::shared_ptr<KIOFuseNode> createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno, QString nameOverride);
	/** Applies a fresh KIO::UDSEntry to an existing node. If the type needs changing,
	 * The old node is deleted and a new one inserted instead. The now fresh node is returned. */
	std::shared_ptr<KIOFuseNode> updateNodeFromUDSEntry(const std::shared_ptr<KIOFuseNode> &node, const KIO::UDSEntry &entry);

	/** Sends the node's attributes with fuse_reply_attr. */
	static void replyAttr(fuse_req_t req, std::shared_ptr<KIOFuseNode> node);
	/** Sends the node entry with fuse_reply_entry and increments the lookup count.
	  * Sends an empty entry if node is null.*/
	void replyEntry(fuse_req_t req, std::shared_ptr<KIOFuseNode> node);

	/** Invokes callback on error or when the bytes are available for reading/writing.
	  * If the file is smaller than bytes, it sets error = ESPIPE. */
	void awaitBytesAvailable(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, off_t bytes, std::function<void(int error)> callback);
	/** Invokes callback on error or when the cache is marked as complete. */
	void awaitCacheComplete(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, std::function<void(int error)> callback);
	/** Invokes callback on error or when all children nodes are available */
	void awaitChildrenComplete(const std::shared_ptr<KIOFuseDirNode> &node, std::function<void(int error)> callback);
	/** Marks a node's cache as dirty and add it to m_dirtyNodes. */
	void markCacheDirty(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node);
	/** Calls the callback once the cache is not dirty anymore (no cache counts as clean as well).
	  * If writes happen while a flush is sending data, a flush will be retriggered. */
	void awaitNodeFlushed(const std::shared_ptr<KIOFuseRemoteCacheBasedFileNode> &node, std::function<void(int error)> callback);
	/** Invokes callback on error or when a node has been refreshed (if its stat timed out) */
	void awaitAttrRefreshed(const std::shared_ptr<KIOFuseNode> &node, std::function<void(int error)> callback);

	/** Returns the override URL for an origin node */
	QUrl makeOriginUrl(QUrl url);
	/** If authority of URL is null, adds an empty authority instead */
	QUrl sanitizeNullAuthority(QUrl url) const;
    
	/** Returns the corresponding FUSE error to the given KIO Job error */
	static int kioErrorToFuseError(const int kioError);

	/** Prevent the Application from quitting. */
	std::unique_ptr<QEventLoopLocker> m_eventLoopLocker;

	/** Struct of implemented fuse operations. */
	struct FuseLLOps;
	static const FuseLLOps fuse_ll_ops;

	/** Fuse bookkeeping. */
	struct fuse_session *m_fuseSession = nullptr;
	/** Fuse bookkeeping. */
	std::unique_ptr<QSocketNotifier> m_fuseNotifier;

	/** Fds of paired sockets. 
	 * Used in conjunction with socket notifier to allow handling signals with the Qt event loop. **/
	static int signalFd[2];
	/** Activated if there is data to read from the fd.
	 * This is the case when a signal handler is activated.**/
	std::unique_ptr<QSocketNotifier> m_signalNotifier;

	/** Used by insertNode for accelerating the search for the next free inode number. */
	fuse_ino_t m_nextIno = KIOFuseIno::DynamicStart;
	/** Map of all known inode numbers to KIOFuseNodes. */
	std::unordered_map<fuse_ino_t, std::shared_ptr<KIOFuseNode>> m_nodes;
	/** Set of all nodes with a dirty cache. */
	std::set<fuse_ino_t> m_dirtyNodes;

	/** @see setUseFileJob() */
	bool m_useFileJob;
};
