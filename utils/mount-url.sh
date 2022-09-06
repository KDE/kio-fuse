#!/bin/sh
# 
#  SPDX-FileCopyrightText: 2022 Alexander Saoutkin <a.saoutkin@gmail.com>
#  SPDX-License-Identifier: GPL-3.0-or-later
#

dbus-send --session --print-reply --type=method_call \
          --dest=org.kde.KIOFuse \
                 /org/kde/KIOFuse \
                 org.kde.KIOFuse.VFS.mountUrl "string:$1"
