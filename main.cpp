/*
   SPDX-FileCopyrightText: 2019-2020 Fabian Vogt <fabian@ritter-vogt.de>
   SPDX-FileCopyrightText: 2019-2020 Alexander Saoutkin <a.saoutkin@gmail.com>
   SPDX-License-Identifier: GPL-3.0-or-later
*/
#include <fuse_lowlevel.h>

#include <QCoreApplication>
#include <QTimer>

#include <KAboutData>
#include <KUiServerJobTracker>

#include "kiofuseservice.h"
#include "kiofuseversion.h"

// Put all custom arguments in here.
// @see https://github.com/libfuse/libfuse/wiki/Option-Parsing
struct kiofuse_config {
	int useFileJob = 1; // on by default
};

#define KIOFUSE_OPT(t, p, v) { t, offsetof(struct kiofuse_config, p), v }

static struct fuse_opt kiofuse_opts[] = {
	KIOFUSE_OPT("--disable-filejob-io", useFileJob, 0),
	FUSE_OPT_END
};

#undef KIOFUSE_OPT

/** A modified version of KUiServerJobTracker which registers jobs after running
  * for more than a specific time. kio-fuse starts quite a lot of jobs, most of them
  * won't need to be shown to the user. While Plasma does some filtering itself based
  * on job duration, the registration itself is quite expensive already. */
class LongRunningJobTracker : public KUiServerJobTracker
{
public:
	void registerJob(KJob *job) override {
		auto timer = new QTimer(job);
		job->connect(job, &KJob::finished, timer, [=] {
			timer->stop();
			timer->deleteLater();
		});
		job->connect(timer, &QTimer::timeout, job, [=] {
			KUiServerJobTracker::registerJob(job);
		});
		timer->start(2000);
	}
	// KUiServerJobTracker::unregisterJob checks whether the job was registered
	// itself already, so it's usable as-is.
};

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
	KIO::setJobTracker(new LongRunningJobTracker);

	KIOFuseService kiofuseservice;

	KAboutData about(QStringLiteral("kiofuse"), QStringLiteral("FUSE Interface for KIO"), QStringLiteral(KIOFUSE_VERSION_STRING));
	KAboutData::setApplicationData(about);

	kiofuseservice.kiofusevfs.setUseFileJob(conf.useFileJob);
	if(!kiofuseservice.start(args, QString::fromUtf8(opts.mountpoint), opts.foreground))
		return 1;

	fuse_opt_free_args(&args);

	return a.exec();
}
