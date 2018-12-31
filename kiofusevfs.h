#ifndef KIOFUSEVFS_H
#define KIOFUSEVFS_H

#include <fuse_lowlevel.h>

#include <functional>
#include <memory>
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
	static void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                    struct fuse_file_info *fi);
	static void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                 struct fuse_file_info *fi);
	static void write(fuse_req_t req, fuse_ino_t ino, const char *buf,
	                  size_t size, off_t off, struct fuse_file_info *fi);

private:
	// Returns nullptr if not found. Ownership remains at m_nodes.
	KIOFuseNode* nodeByName(const KIOFuseNode *parent, const QString name);
	// Returns nullptr if not found. Ownership remains at m_nodes.
	KIOFuseNode* nodeForIno(const fuse_ino_t ino);
	// Takes ownership of the pointer
	fuse_ino_t insertNode(KIOFuseNode *node);
	// Fills a (previously zeroed out) struct stat with minimal information
	void fillStatForFile(struct stat &attr);
	// Creates a new node on the heap with the matching type and fills m_stat fields.
	KIOFuseNode* createNodeFromUDSEntry(const KIO::UDSEntry &entry, const fuse_ino_t parentIno);
	// Invokes callback on error or when the bytes are available for reading/writing.
	// If the file is not as big, it sets error = ESPIPE.
	void waitUntilBytesAvailable(KIOFuseRemoteFileNode *node, size_t bytes, std::function<void(int error)> callback);
	// Handle the _control command in cmd asynchronously and call callback upon completion
	void handleControlCommand(QString cmd, std::function<void(int error)> callback);

	static const struct fuse_lowlevel_ops fuse_ll_ops;

	// Prevent the Application from quitting
	std::unique_ptr<QEventLoopLocker> m_eventLoopLocker;

	struct fuse_session *m_fuseSession = nullptr;
	std::unique_ptr<QSocketNotifier> m_fuseNotifier;
	// Might not actually be free, so check m_nodes first
	fuse_ino_t m_nextIno = KIOFuseIno::DynamicStart;
	std::unordered_map<fuse_ino_t, std::unique_ptr<KIOFuseNode>> m_nodes;
};

#endif // KIOFUSEVFS_H
