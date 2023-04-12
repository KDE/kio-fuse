/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
*/
#include <fuse_lowlevel.h>

#include <QCoreApplication>

#include <KAboutData>

#include "kiofuseservice.h"
#include "kiofuseversion.h"

// Put all custom arguments in here.
// @see https://github.com/libfuse/libfuse/wiki/Option-Parsing
struct kiofuse_config {
	int useFileJob = 1; // on by default
	char *peerAddress = nullptr;
};

#define KIOFUSE_OPT(t, p, v) { t, offsetof(struct kiofuse_config, p), v }

static struct fuse_opt kiofuse_opts[] = {
	KIOFUSE_OPT("--disable-filejob-io", useFileJob, 0),
	KIOFUSE_OPT("--peer=%s", peerAddress, 0),
	FUSE_OPT_END
};

#undef KIOFUSE_OPT

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct kiofuse_config conf;
	struct fuse_cmdline_opts opts;

	fuse_opt_parse(&args, &conf, kiofuse_opts, nullptr);
	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help)
	{
		printf("Usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		printf("    --disable-filejob-io   Don't use FileJob-based (KIO::open) I/O\n");
		printf("    --peer=ADDRESS         Start D-Bus server at ADDRESS instead of using session bus\n");
		return 0;
	}
	else if (opts.show_version)
	{
		printf("KIO FUSE version %s\n", KIOFUSE_VERSION_STRING);
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		return 0;
	}

	QCoreApplication a(argc, argv);
	KIOFuseService kiofuseservice;

	KAboutData about(QStringLiteral("kiofuse"), QStringLiteral("FUSE Interface for KIO"), QStringLiteral(KIOFUSE_VERSION_STRING));
	KAboutData::setApplicationData(about);

	kiofuseservice.kiofusevfs.setUseFileJob(conf.useFileJob);
	const QString peerAddress = conf.peerAddress ? QString::fromUtf8(conf.peerAddress) : QString();
	if(!kiofuseservice.start(args, QString::fromUtf8(opts.mountpoint), opts.foreground, peerAddress))
		return 1;

	fuse_opt_free_args(&args);

	return a.exec();
}
