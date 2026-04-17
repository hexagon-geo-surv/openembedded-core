#! /usr/bin/env python3
#
# Copyright OpenEmbedded Contributors
#
# The script uses another source of CVE information from linux-vulns
# to enrich the cve-summary from cve-check or vex.
# It can also use the list of compiled files from the kernel spdx to ignore CVEs
# that are not affected since the files are not compiled.
#
# It creates a new json file with updated CVE information
#
# Compiled files can be extracted adding the following in local.conf
# SPDX_INCLUDE_COMPILED_SOURCES:pn-linux-yocto = "1"
#
# Tested with the following CVE sources:
# - https://git.kernel.org/pub/scm/linux/security/vulns.git
# - https://github.com/CVEProject/cvelistV5
#
# Example:
# python3 ./openembedded-core/scripts/contrib/improve_kernel_cve_report.py --spdx tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-linux-yocto.spdx.json --kernel-version 6.12.27 --datadir ./vulns
# python3 ./openembedded-core/scripts/contrib/improve_kernel_cve_report.py --spdx tmp/deploy/spdx/3.0.1/qemux86_64/recipes/recipe-linux-yocto.spdx.json --datadir ./vulns --old-cve-report build/tmp/log/cve/cve-summary.json
#
# SPDX-License-Identifier: GPLv2

import argparse
import json
import sys
import logging
import glob
import os
import pathlib
from packaging.version import Version

def is_linux_cve(cve_info):
    '''Return true is the CVE belongs to Linux'''
    if not "affected" in cve_info["containers"]["cna"]:
        return False
    for affected in cve_info["containers"]["cna"]["affected"]:
        if not "product" in affected:
            return False
        if affected["product"] == "Linux" and affected["vendor"] == "Linux":
            return True
    return False

def get_kernel_cves(datadir, compiled_files, version):
    """
    Get CVEs for the kernel
    """
    cves = {}

    check_config = len(compiled_files) > 0

    base_version = Version(f"{version.major}.{version.minor}")

    # Check all CVES from kernel vulns
    pattern = os.path.join(datadir, '**', "CVE-*.json")
    cve_files = glob.glob(pattern, recursive=True)
    not_applicable_config = 0
    fixed_as_later_backport = 0
    vulnerable = 0
    not_vulnerable = 0
    for cve_file in sorted(cve_files):
        cve_info = {}
        with open(cve_file, "r", encoding='ISO-8859-1') as f:
            cve_info = json.load(f)

        if len(cve_info) == 0:
            logging.error("Not valid data in %s. Aborting", cve_file)
            break

        if not is_linux_cve(cve_info):
            continue
        cve_id = os.path.basename(cve_file)[:-5]
        description = cve_info["containers"]["cna"]["descriptions"][0]["value"]
        if cve_file.find("rejected") >= 0:
            logging.debug("%s is rejected by the CNA", cve_id)
            cves[cve_id] = {
                "id": cve_id,
                "status": "Ignored",
                "detail": "rejected",
                "summary": description,
                "description": f"Rejected by CNA"
            }
            continue
        if any(elem in cve_file for elem in ["review", "reverved", "testing", "tmp"]):
            continue

        first_affected, fixed, backport_ver = get_fixed_versions(cve_info, base_version)

        logging.debug("%s: first_affected=%s fixed=%s backport=%s", cve_id, first_affected, fixed, backport_ver)

        if not fixed:
            logging.warning("%s has no known resolution", cve_id)
            cves[cve_id] = {
                "id": cve_id,
                "status": "Unpatched",
                "detail": "known-affected",
                "summary": description,
                "description": "No known resolution"
            }
            vulnerable += 1
            continue
        elif first_affected and version < first_affected:
            logging.debug('%s - fixed-version: only affects %s onwards',
                          cve_id, first_affected)
            cves[cve_id] = {
                "id": cve_id,
                "status": "Patched",
                "detail": "fixed-version",
                "summary": description,
                "description": f"only affects {first_affected} onwards"
            }
            not_vulnerable += 1
        elif fixed <= version:
            logging.debug("%s - fixed-version: Fixed from version %s",
                          cve_id, fixed)
            cves[cve_id] = {
                "id": cve_id,
                "status": "Patched",
                "detail": "fixed-version",
                "summary": description,
                "description": f"Fixed from version {fixed}"
            }
            not_vulnerable += 1
        elif backport_ver and backport_ver <= version:
            logging.debug("%s - cpe-stable-backport: Backported in %s",
                          cve_id, backport_ver)
            cves[cve_id] = {
                "id": cve_id,
                "status": "Patched",
                "detail": "cpe-stable-backport",
                "summary": description,
                "description": f"Backported in {backport_ver}"
            }
            not_vulnerable += 1
        else:
            # Vulnerable - may need backporting
            is_affected = True
            affected_files = []
            if check_config:
                is_affected, affected_files = check_kernel_compiled_files(compiled_files, cve_info)

            if not is_affected and len(affected_files) > 0:
                logging.debug(
                    "%s - not applicable configuration since affected files not compiled: %s",
                    cve_id, affected_files)
                cves[cve_id] = {
                    "id": cve_id,
                    "status": "Ignored",
                    "detail": "not-applicable-config",
                    "summary": description,
                    "description": f"Source code not compiled by config. {sorted(affected_files)}"
                }
                not_applicable_config += 1
            else:
                fixed_in = backport_ver if backport_ver else fixed
                logging.debug("%s needs backporting (fixed from %s)", cve_id, fixed_in)
                cves[cve_id] = {
                    "id": cve_id,
                    "status": "Unpatched",
                    "detail": "version-in-range",
                    "summary": description,
                    "description": f"Needs backporting (fixed from {fixed_in})"
                }
                vulnerable += 1
                if (backport_ver and
                    Version(f"{backport_ver.major}.{backport_ver.minor}") == base_version):
                    fixed_as_later_backport += 1

    logging.info("Total CVEs ignored due to not applicable config: %d", not_applicable_config)
    logging.info("Total CVEs not vulnerable due version-not-in-range: %d", not_vulnerable)
    logging.info("Total vulnerable CVEs: %d", vulnerable)

    logging.info("Total CVEs already backported in %s: %s", base_version,
                    fixed_as_later_backport)
    return cves

def read_spdx(spdx_file):
    '''Open SPDX file and extract compiled files'''
    with open(spdx_file, 'r', encoding='ISO-8859-1') as f:
        spdx = json.load(f)
        if "spdxVersion" in spdx:
            if spdx["spdxVersion"] == "SPDX-2.2":
                return read_spdx2(spdx)
        if "@graph" in spdx:
            return read_spdx3(spdx)
    return []

def read_spdx2(spdx):
    '''
    Read spdx2 compiled files from spdx
    '''
    cfiles = set()
    if 'files' not in spdx:
        return cfiles
    for item in spdx['files']:
        for ftype in item['fileTypes']:
            if ftype == "SOURCE":
                filename = item["fileName"][item["fileName"].find("/")+1:]
                cfiles.add(filename)
    return cfiles

def read_spdx3(spdx):
    '''
    Read spdx3 compiled files from spdx
    '''
    cfiles = set()
    for item in spdx["@graph"]:
        if "software_primaryPurpose" not in item:
            continue
        if item["software_primaryPurpose"] == "source":
            filename = item['name'][item['name'].find("/")+1:]
            cfiles.add(filename)
    return cfiles

def read_debugsources(file_path):
    '''
    Read zstd file from pkgdata to extract sources
    '''
    import zstandard as zstd
    import itertools
    # Decompress the .zst file
    cfiles = set()
    with open(file_path, 'rb') as fh:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(fh) as reader:
            decompressed_bytes = reader.read()
            json_data = json.loads(decompressed_bytes)
            # We need to remove one level from the debug sources
            for source_list in json_data.values():
                for source in source_list:
                    src = source.split("/",1)[1]
                    cfiles.add(src)
    return cfiles

def check_kernel_compiled_files(compiled_files, cve_info):
    """
    Return if a CVE affected us depending on compiled files
    """
    files_affected = set()
    is_affected = False

    for item in cve_info['containers']['cna']['affected']:
        if "programFiles" in item:
            for f in item['programFiles']:
                if f not in files_affected:
                    files_affected.add(f)

    if len(files_affected) > 0:
        for f in files_affected:
            if f in compiled_files:
                logging.debug("File match: %s", f)
                is_affected = True
    return is_affected, files_affected

def get_fixed_versions(cve_info, base_version):
    '''
    Get fixed versionss
    '''
    first_affected = None
    fixed = None
    fixed_backport = None
    next_version = Version(str(base_version) + ".5000")
    for affected in cve_info["containers"]["cna"]["affected"]:
        # In case the CVE info is not complete, it might not have default status and therefore
        # we don't know the status of this CVE.
        if not "defaultStatus" in affected:
            return first_affected, fixed, fixed_backport
        if affected["defaultStatus"] == "affected":
            for version in affected["versions"]:
                v = Version(version["version"])
                if v == Version('0'):
                    #Skiping non-affected
                    continue
                if version["status"] == "unaffected" and first_affected and v < first_affected:
                    first_affected = Version(f"{v.major}.{v.minor}")
                if version["status"] == "affected" and not first_affected:
                    first_affected = v
                elif (version["status"] == "unaffected" and
                    version['versionType'] == "original_commit_for_fix"):
                    fixed = v
                elif base_version < v and v < next_version:
                    fixed_backport = v
        elif affected["defaultStatus"] == "unaffected":
            # Only specific versions are affected. We care only about our base version
            if "versions" not in affected:
                continue
            for version in affected["versions"]:
                if "versionType" not in version:
                    continue
                if version["versionType"] == "git":
                    continue
                v = Version(version["version"])
                # in case it is not in our base version
                less_than = Version(version["lessThan"])

                if not first_affected:
                    first_affected = v
                fixed = less_than
                if base_version < v and v < next_version:
                    fixed_backport = less_than

    return first_affected, fixed, fixed_backport

def copy_data(old, new):
    '''Update dictionary with new entries, while keeping the old ones'''
    for k in new.keys():
        old[k] = new[k]
    return old

# Function taken from cve_check.bbclass. Adapted to cve fields
def cve_update(cve_data, cve, entry):
    # If no entry, just add it
    if cve not in cve_data:
        cve_data[cve] = entry
        return
    # If we are updating, there might be change in the status
    if cve_data[cve]['status'] == "Unknown":
        cve_data[cve] = copy_data(cve_data[cve], entry)
        return
    if cve_data[cve]['status'] == entry['status']:
        cve_data[cve] = copy_data(cve_data[cve], entry)
        return
    if entry['status'] == "Unpatched" and cve_data[cve]['status'] == "Patched":
        # Backported-patch (e.g. vendor kernel repo with cherry-picked CVE patch)
        # has priority over unpatch from CNA
        if "detail" in cve_data and cve_data[cve]['detail'] == "backported-patch":
            return
        logging.warning("CVE entry %s update from Patched to Unpatched from the scan result", cve)
        cve_data[cve] = copy_data(cve_data[cve], entry)
        return
    if entry['status'] == "Patched" and cve_data[cve]['status'] == "Unpatched":
        logging.warning("CVE entry %s update from Unpatched to Patched from the scan result", cve)
        cve_data[cve] = copy_data(cve_data[cve], entry)
        return
    # If we have an "Ignored", it has a priority
    if cve_data[cve]['status'] == "Ignored":
        logging.debug("CVE %s not updating because Ignored", cve)
        return
    # If we have an "Ignored", it has a priority
    if entry['status'] == "Ignored":
        cve_data[cve] = copy_data(cve_data[cve], entry)
        logging.debug("CVE entry %s updated from Unpatched to Ignored", cve)
        return
    logging.warning("Unhandled CVE entry update for %s %s from %s %s to %s",
        cve, cve_data[cve]['status'], cve_data[cve]['detail'],  entry['status'], entry['detail'])

def main():
    parser = argparse.ArgumentParser(
        description="Update cve-summary with kernel compiled files and kernel CVE information"
    )
    parser.add_argument(
        "-s",
        "--spdx",
        help="SPDX2/3 for the kernel. Needs to include compiled sources",
    )
    parser.add_argument(
        "--debug-sources-file",
        help="Debug sources zstd file generated from Yocto",
    )
    parser.add_argument(
        "--datadir",
        type=pathlib.Path,
        help="Directory where CVE data is",
        required=True
    )
    parser.add_argument(
        "--old-cve-report",
        help="CVE report to update. (Optional)",
    )
    parser.add_argument(
        "--kernel-version",
        help="Kernel version. Needed if old cve_report is not provided (Optional)",
        type=Version
    )
    parser.add_argument(
        "--new-cve-report",
        help="Output file",
        default="cve-summary-enhance.json"
    )
    parser.add_argument(
        "-D",
        "--debug",
        help='Enable debug ',
        action="store_true")

    args = parser.parse_args()

    if args.debug:
        log_level=logging.DEBUG
    else:
        log_level=logging.INFO
    logging.basicConfig(format='[%(filename)s:%(lineno)d] %(message)s', level=log_level)

    if not args.kernel_version and not args.old_cve_report:
        parser.error("either --kernel-version or --old-cve-report are needed")
        return -1

    # by default we don't check the compiled files, unless provided
    compiled_files = []
    if args.spdx:
        compiled_files = read_spdx(args.spdx)
        logging.info("Total compiled files %d", len(compiled_files))
    if args.debug_sources_file:
        compiled_files = read_debugsources(args.debug_sources_file)
        logging.info("Total compiled files %d", len(compiled_files))

    if args.old_cve_report:
        with open(args.old_cve_report, encoding='ISO-8859-1') as f:
            cve_report = json.load(f)
    else:
        #If summary not provided, we create one
        cve_report = {
            "version": "1",
            "package": [
                {
                    "name": "linux-yocto",
                    "version": str(args.kernel_version),
                    "products": [
                        {
                            "product": "linux_kernel",
                            "cvesInRecord": "Yes"
                        }
                    ],
                    "issue": []
                }
            ]
        }

    for pkg in cve_report['package']:
        is_kernel = False
        for product in pkg['products']:
            if product['product'] == "linux_kernel":
                is_kernel=True
        if not is_kernel:
            continue
        # We remove custom versions after -
        upstream_version = Version(pkg["version"].split("-")[0])
        logging.info("Checking kernel %s", upstream_version)
        kernel_cves = get_kernel_cves(args.datadir,
                                      compiled_files,
                                      upstream_version)
        logging.info("Total kernel cves from kernel CNA: %s", len(kernel_cves))
        cves = {issue["id"]: issue for issue in pkg["issue"]}
        logging.info("Total kernel before processing cves: %s", len(cves))

        for cve in kernel_cves:
            cve_update(cves, cve, kernel_cves[cve])

        pkg["issue"] = []
        for cve in sorted(cves):
            pkg["issue"].extend([cves[cve]])
        logging.info("Total kernel cves after processing: %s", len(pkg['issue']))

    with open(args.new_cve_report, "w", encoding='ISO-8859-1') as f:
        json.dump(cve_report, f, indent=2)

    return 0

if __name__ == "__main__":
    sys.exit(main())

