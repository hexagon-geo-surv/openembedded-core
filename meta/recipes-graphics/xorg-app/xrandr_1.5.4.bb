# FIXME: the LIC_FILES_CHKSUM values have been updated by 'devtool upgrade'.
# The following is the difference between the old and the new license text.
# Please update the LICENSE value if needed, and summarize the changes in
# the commit message via 'License-Update:' tag.
# (example: 'License-Update: copyright years updated.')
#
# The changes:
#
# --- COPYING
# +++ COPYING
# @@ -1,6 +1,8 @@
#  Copyright © 2001 Keith Packard, member of The XFree86 Project, Inc.
#  Copyright © 2002 Hewlett Packard Company, Inc.
#  Copyright © 2006 Intel Corporation
# +Copyright © 2008 Keith Packard
# +Copyright © 2013 NVIDIA Corporation
#  
#  Permission to use, copy, modify, distribute, and sell this software and its
#  documentation for any purpose is hereby granted without fee, provided that
# 
#

require xorg-app-common.inc

SUMMARY = "XRandR: X Resize, Rotate and Reflect extension command"

DESCRIPTION = "Xrandr is used to set the size, orientation and/or \
reflection of the outputs for a screen. It can also set the screen \
size."

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://COPYING;md5=97a36d5c66965b1cea4666b3708ca6e8"
DEPENDS += "libxrandr libxrender"
PE = "1"

SRC_URI_EXT = "xz"
SRC_URI[sha256sum] = "2cafccb2aaf2491a4068676117a0d4f90ab307724b96fffc54cd1da953779400"

BBCLASSEXTEND = "native nativesdk"
