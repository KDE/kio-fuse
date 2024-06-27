# KIO FUSE

[FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
interface for [KIO](https://api.kde.org/frameworks/kio/html/).

## Build and Install KIO FUSE

Here we describe how to compile, test, run and install KIO FUSE from source.

### Build Dependencies

To install build dependencies on Void Linux:

    xbps-install -Sy base-devel fuse3 cmake extra-cmake-modules qt5 qt5-devel kio kcoreaddons-devel kcoreaddons kio-devel fuse3 fuse3-devel

(and qt6 build deps, `cmake extra-cmake-modules  kf6-kio kf6-kio-devel base-devel fuse3 fuse3-devel qt6-base qt6-base-devel kf6-kcoreaddons kf6-kcoreaddons-devel`)

(and `kio-extras` for running certain tests)

To install build dependencies on Arch Linux:

    pacman -S base-devel fuse3 cmake extra-cmake-modules qt5base kio

(and `kio-extras` for running certain tests)

To install build dependencies on Fedora 32:

    dnf install cmake extra-cmake-modules kf5-kio-devel fuse3-devel 
    qt5-qtbase-devel pkg-config

(and `kio-extras` for running certain tests)

To install build dependencies on openSUSE Tumbleweed:

    zypper install extra-cmake-modules 'cmake(KF5KIO)' 'pkgconfig(fuse3)' 
    kio-devel 'cmake(Qt5Test)' 'cmake(Qt5Dbus)'

(and `kio-extras5` for running certain tests)

To install build dependencies on Ubuntu 19.04:

    apt install fuse3 libfuse3-dev build-essential cmake extra-cmake-modules
    pkg-config libkf5kio-dev

(and `kio-extras` for running certain tests)

### Build Steps

Once you have installed the build dependencies one can build KIO FUSE
itself.

In the root of the git repository run the following:

```
mkdir build; cd build; cmake .. && make`
```

### Running Tests

In the build directory run the following:

```
make test
```

For more verbose output run the following:

```
make tests ARGS=-V
```

### Installing KIO FUSE

In the build directory run the following:

```
make install
```

## Usage

This section describes how to start KIO FUSE via DBus activation and
by simply running it manually.

### KIO FUSE DBus Activation

KIO FUSE is a DBus activated service, so for permanent installation the
installed service file has to be in a directory used by `dbus-daemon`.
If you're installing into a custom prefix, you may want to link
`[prefix]/share/dbus-1/services/org.kde.KIOFuse.service` into
`~/.local/share/dbus-1/services/` and
`[prefix]/lib/systemd/user/kio-fuse.service` into
`~/.local/share/systemd/user/`.

To make sure that the installed version is actually used, stop any already
running instance with `killall kio-fuse` and log out and in again.

For quick testing, installation and DBus activation can be skipped. Instead,
after stopping any previously running instance, start the built `kio-fuse` binary
with the `-f` parameter and possibly other options.

The DBus service is automatically used by KIO (5.66+) when opening a file on a
KIO URL with a KIO-unaware application.

### Running KIO FUSE manually

Create a new directory somewhere, make sure that no daemon is going to clean
up after it (like `systemd-tmpfiles` in `/run/user/...`) and run `kio-fuse -d $dir`.
The `-d` means that it shows debug output and does not daemonize - that makes it
easier to use it at first.

In your session bus you'll find a `org.kde.KIOFuse` service with an interface that
allows one to communicate with the `kio-fuse` process.

Let's assume you want to make the files at
`ftp://user:password@server/directory` accessible in your local file system.
To send the corresponding mount command, you can use our utility script [`utils/mount-url.sh`](./utils/mount-url.sh) as follows:
```
mount-url.sh ftp://user:password@server/directory
```
Alternatively, you can simply use `dbus-send` (which is what `mount-url.sh` uses anyway):
```
dbus-send --session --print-reply --type=method_call \
          --dest=org.kde.KIOFuse \
                 /org/kde/KIOFuse \
                 org.kde.KIOFuse.VFS.mountUrl string:ftp://user:password@server/directory
```

If it failed, KIO FUSE will reply with an appropriate error message. If it
succeeded, you will get the location that the URL is mounted on as a reply. In
this case it would be `$dir/ftp/user@server/directory` and the directory will be
accessibly at that URL.

After your work is done, simply run `fusermount3 -u $dir` to unmount the URL and
exit `kio-fuse`.

Have a lot of fun!
