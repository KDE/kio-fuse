#ifndef KIOFUSEVFS_H
#define KIOFUSEVFS_H

#include <fuse_lowlevel.h>

#include <memory>
#include <unordered_map>

#include <QObject>
#include <QSocketNotifier>

#include "kiofusenode.h"

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

public slots:
	void fuseRequestPending();

private:
	static void lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
	static void forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
	static void getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
	static void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	                    struct fuse_file_info *fi);

private:
	KIOFuseNode *nodeForIno(const fuse_ino_t ino);

	static const struct fuse_lowlevel_ops fuse_ll_ops;

	struct fuse_session *m_fuseSession = nullptr;
	QSocketNotifier *m_fuseNotifier = nullptr;
	std::unordered_map<fuse_ino_t, std::unique_ptr<KIOFuseNode>> m_nodes;
};

#endif // KIOFUSEVFS_H
