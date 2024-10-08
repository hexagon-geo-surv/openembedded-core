SUMMARY = "Utility library to parse, compare, simplify and normalize license expressions"
HOMEPAGE = "https://github.com/nexB/license-expression"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://apache-2.0.LICENSE;md5=86d3f3a95c324c9479bd8986968f4327"

SRC_URI[sha256sum] = "60d5bec1f3364c256a92b9a08583d7ea933c7aa272c8d36d04144a89a3858c01"

inherit pypi ptest python_setuptools_build_meta
PYPI_PACKAGE = "license_expression"

DEPENDS += "python3-setuptools-scm-native"

RDEPENDS:${PN} += "\
    python3-booleanpy \
    python3-core \
    python3-json \
    python3-stringold \
    python3-logging \
"

BBCLASSEXTEND = "native nativesdk"

SRC_URI += " \
	file://run-ptest \
"

RDEPENDS:${PN}-ptest += " \
	python3-pytest \
	python3-unittest-automake-output \
"

do_install_ptest() {
    install -d ${D}${PTEST_PATH}/tests
    install -d ${D}${PTEST_PATH}/src
    cp -rf ${S}/tests/* ${D}${PTEST_PATH}/tests/
    cp -rf ${S}/src/* ${D}${PTEST_PATH}/src/
    cp -rf ${S}/setup.cfg ${D}${PTEST_PATH}/
}
