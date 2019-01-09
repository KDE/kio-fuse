#ifndef KIOFUSEVFS_H
#define KIOFUSEVFS_H

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
	// Defined by the kernel
	Invalid = 0,
	Root = 1,

	// Fixed by KIOFuse
	DeletedRoot,
	Control,

	// Dynamic allocation starts here
	DynamicStart,
};

class KIOFuseVFS : public QObject
{
	Q_OBJECT
public:
	explicit KIOFuseVFS(QObject *parent = nullptr);
	~KIOFuseVFS();

	bool start(fuse_args &args, const char *mountpoint);
	void stop();

public Q_SLOTS:
	void fuseRequestPending();

private:
	// Functions used by fuse_lowlevel_ops
	static void lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
	static void forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
	static void getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi);
	static void readlink(fuse_req_t req, fuse_ino_t ino);
	static void mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
	static void symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);
	static void rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
	                   const char *newname, unsigned int flags);
	static void open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                    struct fuse_file_info *fi);
	static void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                 struct fuse_file_info *fi);
	static void write(fuse_req_t req, fuse_ino_t ino, const char *buf,
	                  size_t size, off_t off, struct fuse_file_info *fi);
	static void flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);

private:
	// Returns nullptr if not found. Ownership remains at m_nodes.
	KIOFuseNode* nodeByName(const KIOFuseNode *parent, const QString name);
	// Returns nullptr if not found. Ownership remains at m_nodes.
	KIOFuseNode* nodeForIno(const fuse_ino_t ino);
	// Removes the node from the old parent's children list (if it has a parent) and adds it to the new parent.
	void reparentNode(KIOFuseNode *node, fuse_ino_t newParentIno);
	// Takes ownership of the pointer
	fuse_ino_t insertNode(KIOFuseNode *node);
	// Fills a (previously zeroed out) struct stat with minimal information
	void fillStatForFile(struct stat &attr);
	// Adjusts the lookup count and deletes the node if it is now zero and a child of DeletedRoot.
	void incrementLookupCount(KIOFuseNode *node, uint64_t delta=1);
	void decrementLookupCount(KIOFuseNode *node, uint64_t delta=1);
	// Depending on the lookup count, it makes the node a child of DeletedRoot or deletes it directly.
	void markNodeDeleted(KIOFuseNode *node);
	// Sends the struct attr to fuse
	static void replyAttr(fuse_req_t req, KIOFuseNode *node);
	// Creates a new node on the heap with the matching type and fills m_stat fields.
	KIOFuseNode* createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno, QString nameOverride={});
	// Invokes callback on error or when the bytes are available for reading/writing.
	// If the file is not as big, it sets error = ESPIPE.
	void waitUntilBytesAvailable(KIOFuseRemoteFileNode *node, size_t bytes, std::function<void(int error)> callback);
	// Invokes callback on error or when all children nodes are available
	void waitUntilChildrenComplete(KIOFuseDirNode *node, std::function<void(int error)> callback);
	// Runs KIO::stat on url and adds a node to the tree if successful. Calls the callback at the end.
	void mountUrl(QUrl url, std::function<void(KIOFuseNode *node, int error)> callback);
	// Handle the _control command in cmd asynchronously and call callback upon completion or failure.
	void handleControlCommand(QString cmd, std::function<void(int error)> callback);
	// If the cache is dirty, writes the local cache to the remote. Callback is called on success, failure
	// or if cache was not dirty.
	void flushRemoteNode(KIOFuseRemoteFileNode *node, std::function<void(int error)> callback);

	static const struct fuse_lowlevel_ops fuse_ll_ops;

	// Prevent the Application from quitting
	std::unique_ptr<QEventLoopLocker> m_eventLoopLocker;

	struct fuse_session *m_fuseSession = nullptr;
	std::unique_ptr<QSocketNotifier> m_fuseNotifier;

	// Set of nodes that need flushing
	std::set<fuse_ino_t> m_dirtyNodes;

	// Might not actually be free, so check m_nodes first
	fuse_ino_t m_nextIno = KIOFuseIno::DynamicStart;
	// Map of all known inodes to KIOFuseNodes
	std::unordered_map<fuse_ino_t, std::unique_ptr<KIOFuseNode>> m_nodes;
};

#endif // KIOFUSEVFS_H
