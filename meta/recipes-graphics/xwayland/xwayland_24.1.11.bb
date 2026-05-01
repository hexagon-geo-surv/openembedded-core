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
# @@ -314,6 +314,11 @@
#  OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#  
# +Except as contained in this notice, the name of Silicon Graphics, Inc.
# +shall not be used in advertising or otherwise to promote the sale, use or
# +other dealings in this Software without prior written authorization from
# +Silicon Graphics, Inc.
# +
#  
#  Copyright (c) 1994, 1995  Hewlett-Packard Company
#  
# @@ -1778,6 +1783,8 @@
#  USE OR OTHER DEALINGS IN THE SOFTWARE.
#  
#  
# +Author: Eamon Walsh <ewalsh@tycho.nsa.gov>
# +
#  Permission to use, copy, modify, distribute, and sell this software and its
#  documentation for any purpose is hereby granted without fee, provided that
#  this permission notice appear in supporting documentation.  This permission
# 
#

SUMMARY = "XWayland is an X Server that runs under Wayland."
DESCRIPTION = "XWayland is an X Server running as a Wayland client, \
and thus is capable of displaying native X11 client applications in a \
Wayland compositor environment. The goal of XWayland is to facilitate \
the transition from X Window System to Wayland environments, providing \
a way to run unported applications in the meantime."
HOMEPAGE = "https://fedoraproject.org/wiki/Changes/XwaylandStandalone"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://COPYING;md5=f8778cfcd90ece0e4b225f30182227ca"

SRC_URI = "https://www.x.org/archive/individual/xserver/xwayland-${PV}.tar.xz"
SRC_URI[sha256sum] = "27115a1a8819078409bf6fecfeb7724e8137bd36426de7005a5b3aae0a2138ff"

UPSTREAM_CHECK_REGEX = "xwayland-(?P<pver>\d+(\.(?!90\d)\d+)+)\.tar"

inherit meson features_check pkgconfig
REQUIRED_DISTRO_FEATURES = "x11 opengl"

DEPENDS += "xorgproto xtrans pixman libxkbfile libxfont2 wayland wayland-native wayland-protocols libdrm libepoxy libxcvt libtirpc"

OPENGL_PKGCONFIGS = "glx glamor dri3"
PACKAGECONFIG ??= "${XORG_CRYPTO} ${XWAYLAND_EI} \
                   ${@bb.utils.contains('DISTRO_FEATURES', 'opengl', '${OPENGL_PKGCONFIGS}', '', d)} \
"
PACKAGECONFIG[dri3] = "-Ddri3=true,-Ddri3=false,libxshmfence"
PACKAGECONFIG[libdecor] = "-Dlibdecor=true,-Dlibdecor=false,libdecor"
PACKAGECONFIG[glx] = "-Dglx=true,-Dglx=false,virtual/libgl virtual/libx11"
PACKAGECONFIG[glamor] = "-Dglamor=true,-Dglamor=false,libepoxy virtual/libgbm,libegl"
PACKAGECONFIG[unwind] = "-Dlibunwind=true,-Dlibunwind=false,libunwind"
PACKAGECONFIG[xinerama] = "-Dxinerama=true,-Dxinerama=false"

# Xorg requires a SHA1 implementation, pick one
XORG_CRYPTO ??= "openssl"
PACKAGECONFIG[openssl] = "-Dsha1=libcrypto,,openssl"
PACKAGECONFIG[nettle] = "-Dsha1=libnettle,,nettle"
PACKAGECONFIG[gcrypt] = "-Dsha1=libgcrypt,,libgcrypt"
XWAYLAND_EI ??= "xwayland_ei_false"
PACKAGECONFIG[xwayland_ei_false] = "-Dxwayland_ei=false"
PACKAGECONFIG[xwayland_ei_portal] = "-Dxwayland_ei=portal,,libei"
PACKAGECONFIG[xwayland_ei_socket] = "-Dxwayland_ei=socket,,libei"

do_install:append() {
    # remove files not needed and clashing with xserver-xorg
    rm -rf ${D}/${libdir}/xorg/
}

FILES:${PN} += "${libdir}/xorg/protocol.txt"

RDEPENDS:${PN} += "xkbcomp ${@bb.utils.contains("DISTRO_FEATURES", "systemd", "", "x11-volatiles", d)}"

CVE_STATUS[CVE-2024-21886] = "fixed-version: fixed since xwayland-23.2.4"
