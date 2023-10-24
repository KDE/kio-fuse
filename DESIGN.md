# Design of KIO FUSE

This file explains the internal implementation only, please read the README
first to learn about the external interface.

## Goals

KIO FUSE's design is based on these requirements:

* Maximum compatibility with applications (as far as KIO allows).
* Work with most protocols: The minimum set of operations a worker must support
  are `KIO::stat` and `KIO::get`.
* Good usability: this means mostly acceptable speed (using caching whereever
  possible), but also having a simple API to the outside world.
* Security: the password of mounted URLs is not obviously visible.
* Keep It Simple Stupid (KISS).

## Use of the `libfuse` low-level API

Compared to the "old" version of KIO FUSE in SVN, this implementation has a
major difference in the implementation: instead of the high-level `libfuse` API,
which translates the inode numbers passed from the kernel to paths for calling
the operations, the lowlevel `libfuse` API is used.

While it may look like translating paths to URLs is much easier than keeping
track of inode numbers, the high-level API has actually completely different
behaviour in many other ways, which actually makes it much more complex to use.
The most important difference is that the lowlevel API can be used
asynchronously, which makes it possible to process multiple requests in one
thread. This matches the Qt (and thus KIO) event processing model perfectly.
This means that multithreading is not required (KIO works on the main thread
anyway), resulting in no need for locking and passing queues around.

Additonally, a design flaw in `libfuse` means that it's impossible to keep track
of the lookup count correctly/race-free when using multiple threads:
[Move Lookup Count Management into LLFUSE?](https://github.com/python-llfuse/python-llfuse/blob/master/developer-notes/lookup_counts.rst)

The additional `lookup` lowlevel operation makes it possible to avoid calling
`readdir` on all path elements when opening a file for the first time.
Example: `smb://host/dir/subdir/file` is mounted as `smb/host/dir/subdir/file`.
When opening that for the first time with the high-level API, it would result in
these calls: `opendir(/) -> readdir(/) -> closedir(/) -> opendir(smb) -> ...`
This is because `libfuse` has to build an internal tree model for mapping inode
numbers to path elements.
With the lowlevel API, lookup is enough: `lookup(/, smb) -> lookup(smb, host)...`
This can be implemented using `KIO::stat` instead of a full `KIO::listDir`, both on
the initial access and when the node already exists locally, to recheck whether
the local representation still matches.
With the high-level API, lookup on existing nodes is not passed to the FS
implementation if the node is part of the internal tree already. This makes
it harder (if not infeasible) to react to changes on the remote side, e.g.
deletes or renames.

Not using inode numbers in the high-level API means that implementing unlink
properly (i.e. already opened file handles are still valid) is not possible,
so instead of calling unlink directly, `libfuse` renames deleted files as
`.fuse_hiddenXXX` and deletes them when their lookup count drops to zero.
By using the low-level API, implementing deletion is up to the filesystem.

## The VFS node tree

Downside of the lowlevel API is that the inode number &rarr; path mapping has to be
implemented by the filesystem. For implementing local caching of nodes having
a tree structure is necessary anyway though, so this does not actually make it
more complex.

The tree is implemented as a `std::unordered_map` of `fuse_ino_t` to `KIOFuseNode`.
Each node knows about its parent and children inode numbers. The two root nodes
have an invalid inode number (0) set as parent.
For details on the class hierarchy and their members, read
[kiofusenode.h](./kiofusenode.h).

For carrying out special operations depending on the node type, RTTI is used,
by either querying the typeid or doing a `dynamic_cast`.

During runtime, the tree can look like this:

```
"" (ino: 1)
KIOFuseDirNode
    |
    |        "smb"
    |------> KIOFuseDirNode
    |           \
    |            \        "user@fileserver01"       "a file"
    |             ------> KIOFuseRemoteDirNode -----> KIOFuseRemoteFileNode
    |                    "user:pass@fileserver01"
    |                         \
    |                          \        "directory"
    |                           ------> KIOFuseRemoteDirNode
    |                                       \
    |                                        \        "another file"
    |                                         ------> KIOFuseRemoteFileNode
    |
    |       "sftp"
    ------> KIOFuseDirNode
            \
            \        "user@someserver"         "a file"
            ------> KIOFuseRemoteDirNode -----> KIOFuseRemoteFileNode
                    "user:pass@someserver"

"" (ino: 2)           "deleted file"
KIOFuseDirNode ----> KIOFuseRemoteFileNode
```

The root node with inode number 1 represents the root of the VFS.
Only files below are visible in the VFS hierarchy.

Note that `RemoteFileNode` is an abstract class. At runtime, it will actually be
instantiated as one of its subclasses (`KIOFuseRemoteCacheBasedNode` or
`KIOFuseRemoteFileJobBasedNode`). The type of class instantiated will depend on
the URL of the file. Please see the [File IO](#file-io) section to learn more.

Remote nodes (`KIOFuseRemote*Node`) are derived from `KIOFuseRemoteFileInfo` in
addition to the base node type, which contains some members specific for remote
access.

`m_overrideUrl` is used to implement URL mountpoints and redirections. To get the
remote URL of a node, the tree is traversed upwards until an override is found
and the path is appended.

`m_lastStatRefresh` stores the time when `m_stat` was updated last. It's updated
on node construction and by `updateNodeFromUDSEntry` and queried by the
`awaitAttrRefreshed` method.

## Mounting a URL

Goal of mounting a URL is to make the target file/directory reachable over the
FUSE filesystem. The first step is to verify that the target actually exists,
if that is not the case an error is returned without doing any changes.

If the target is reachable, the next step is to find which part of the URL
(from left to right) is the first accessible one. This is needed as ioworkers
like `tar` do not support listing `tar:///` and instead need some part of the path
to return results. This minimum URL is the "origin" and a `KIOFuseRemoteDirNode`
with the origin as `m_overrideUrl` is created, with the parents as plain
`KIOFuseDirNode`s.

The local path to this origin node with the path from the origin to the target
node is returned. Note that at this point this node doesn't actually exist
locally though, only everything up until (including) the origin. To reach the
rest, the kernel does lookup operations which trigger `KIO::stat` and node
creation for each path component.

Initially, mounting was implemented in a different way, to only require a
single `KIO::stat` call for determining accessibility and the target node's
attributes. All path components except the final one were assumed to be
traversable directories, but this assumption doesn't hold for symlinks. By
letting the kernel deal with path traversal, symlinks returned by lookup are
handled correctly.

## Unlinking a node

The root node with inode number 2 is used as a parent for deleted, but still
opened (non-zero lookup count) nodes. This is used for proper unlinking.
When the loopup count of a node below the "deleted root" drops to zero, the
node is deleted, i.e. the inode number can be reused and memory is freed.
When unlinking a node which already has a lookup count of zero, it is directly
deleted.

## General anatomy of a write operation

All write operations are implemented by verifying the parameters locally (if
possible at all) and then starting the operation to KIO. Once the operation
completes, either an error is sent or the change is done in the local VFS tree
and the result is sent.

```cpp
void KIOFuseVFS::operation(fuse_req_t req, fuse_ino_t inode, ...)
{
    KIOFuseVFS *that = reinterpret_cast<KIOFuseVFS*>(fuse_req_userdata(req));
    auto node = that->nodeForIno(parent);
    if(!node) complain and return;

    auto job = KIO::operation(that->remoteUrl(node), ...);
    connect(job, &finished, [=] {
        if(job->error())
            fuse_reply_err(req, kioErrorToFuseError(job->error()));
        else
        {
            that->doOperation(node);
            fuse_reply_result(req, ...);
        }
    });
}
```

## Permissions

While the `st_uid`/`st_gid`/`st_mode` fields of nodes are used from KIO if possible,
access is not checked by `kio-fuse` at all. Instead, KIO returns errors if an
operation fails because of missing permissions and those are simply forwarded.

## Node attributes

For every node in the VFS, the full `struct stat` is already available when
inserting it into the tree. This happens when mounting a URL (uses `KIO::stat`)
and when requesting the children of a URL (using `KIO::listDir` with details).
The same is true of the symlink's target path.

As a result, `getattr` and `readlink` are non-blocking if the node's attributes
have not timed out.

`setattr` instead does block, it only returns if all of the requested operations
(e.g. `SET_ATTR_MTIME`, `SET_ATTR_MODE`, `SET_ATTR_UID`) completed.

## Directory operations

To support the optimization possibility the lookup operation in the low-level
API offers, children of `KIOFuseRemoteDirNode` are loaded lazily. This means
that the full list of children is only requested (using `KIO::listDir`) if
required, so if lookup on the directory fails or if readdir is executed.

A node's children are considered valid for 30 seconds. The last time a node
was dir listed via `KIO::listDir` is stored in `m_lastChildrenRefreshed`.
Each readdir request checks if they have timed out via the
`haveChildrenTimedOut()` method and updates the children (and consequently, their
attributes) as appropriate. This is implemented in `awaitChildrenComplete`.

## Node Expiration

Each remote node has a timeout on its attributes and its children, which is
currently set to 30 seconds.

When a node's attributes are requested, the `awaitAttrRefreshed` method checks
whether the attributes expired and if so, calls `mountUrl` to refresh it via
`updateNodeFromUDSEntry`. If the result of `KIO::stat` indicates that the node does
not exist on the remote side anymore it is (recursively) marked as deleted.
Otherwise, a new node based on the fresh attributes is created and if the type
matches, used to update the existing node. If the type does not match, the old
node is marked as deleted and the new node inserted into the tree.

For directories, `awaitChildrenComplete` calls `KIO::listDir` for refreshing the
list of children, either removing vanished nodes, creating new nodes or
updating existing ones using the same method as outlined above.

## File IO

File IO is done in either of two ways, depending on what the protocol supports.
If the protocol supports `KIO::open` (and all of its operations, which at the time
of writing is `read`/`write`/`seek`/`truncate`) then IO will be based upon KIO's `FileJob`.
KIO's `FileJob` interface allows random-access IO, and hence all `read`, `write` and
`truncate` requests are simply forwarded to the corresponding `FileJob` functions.

Whilst improving performance for larger files compared to the cache-based IO
described below, the performance of individual `read`/`write`/`truncate` requests
if significantly reduced.

The protocols that currently support `KIO::open` are `file`/`sftp`/`smb`.

Otherwise, file IO is implemented completely on top of a file based cache.
On the first read or write access to a non truncated file, the whole file is
downloaded into a new temporary file and all readers are notified on cache
completeness changes (see `awaitBytesAvailable`).

Therefore the read and write ops itself are trivial, they just forward the
IO operation to the temporary file once enough data is available.

On each write to a file, the file is marked as dirty and added to the set
of dirty nodes. On various occasions, `awaitNodeFlushed` is called which removes
the node from the dirty set and starts a `KIO::put` for the file. On success,
it is checked whether a write occured during flushing and if so, another
flush is started. This is repeated until the node was still marked as clean
on finish.

When there a no open file descriptors to a node anymore, the cache is flushed
if necessary and then dropped.

## Hardlinks

Hardlinks are not supported well in the current design of KIO so they were
simply not considered during KIO FUSE development either.

While inode and device numbers can be returned are part of UDSEntries returned
from workers, neither `stat.st_link` nor `::link` are accessible.
