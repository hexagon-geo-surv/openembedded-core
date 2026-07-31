SUMMARY = "Test recipe for multiple git SRC_URI entries with nested destsuffix values"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

# Three git entries genuinely nested inside each other's working tree (not just
# nested by path under a shared plain directory): level2's destsuffix places it
# inside level1's checkout, and level3's destsuffix places it inside level2's.
# This exercises the devtool code path that must convert every nested git repo
# to a standalone clone even when one repo's checkout lives inside another
# repo's working tree: the initial fetch uses a shared clone whose alternates
# point into downloads/git2/; git repack copies those objects locally so the
# workspace survives 'bitbake -c cleanall'.
SRC_URI = "git://git.yoctoproject.org/dbus-wait;nobranch=1;protocol=https;name=level1;destsuffix=level1 \
    git://git.yoctoproject.org/dbus-wait;nobranch=1;protocol=https;name=level2;destsuffix=level1/level2 \
    git://git.yoctoproject.org/dbus-wait;nobranch=1;protocol=https;name=level3;destsuffix=level1/level2/level3 \
"

SRCREV_level1 = "64bc7c8fae61ded0c4e555aa775911f84c56e438"
SRCREV_level2 = "64bc7c8fae61ded0c4e555aa775911f84c56e438"
SRCREV_level3 = "64bc7c8fae61ded0c4e555aa775911f84c56e438"
SRCREV_FORMAT = "level1_level2_level3"

S = "${UNPACKDIR}"

do_configure[noexec] = "1"
do_compile[noexec] = "1"
do_install[noexec] = "1"
