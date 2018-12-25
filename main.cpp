#include <fuse_lowlevel.h>

#include <QSocketNotifier>
#include <QCoreApplication>

#include "kiofusevfs.h"

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		return 0;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		return 0;
	}

	QCoreApplication a(argc, argv);
	KIOFuseVFS kiofusevfs;
	if(!kiofusevfs.start(args, opts.mountpoint))
		return 1;

	fuse_opt_free_args(&args);

	return a.exec();
}
