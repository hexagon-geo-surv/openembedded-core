# Checks related to the patch's LIC_FILES_CHKSUM  metadata variable
#
# Copyright (C) 2016 Intel Corporation
#
# SPDX-License-Identifier: GPL-2.0-only

import base
import collections
import os
import patchtest_patterns
import pyparsing
from patchtest_parser import PatchtestParser

# Data store commonly used to share values between pre and post-merge tests
PatchTestDataStore = collections.defaultdict(str)

class TestMetadata(base.Metadata):

    def test_license_presence(self):
        if not self.added:
            self.skip('No added recipes, skipping test')

        # TODO: this is a workaround so we can parse the recipe not
        # containing the LICENSE var: add some default license instead
        # of INVALID into auto.conf, then remove this line at the end
        auto_conf = os.path.join(os.environ.get('BUILDDIR'), 'conf', 'auto.conf')
        open_flag = 'w'
        if os.path.exists(auto_conf):
            open_flag = 'a'
        with open(auto_conf, open_flag) as fd:
            for pn in self.added:
                fd.write('LICENSE ??= "%s"\n' % patchtest_patterns.invalid_license)

        no_license = False
        for pn in self.added:
            rd = self.tinfoil.parse_recipe(pn)
            license = rd.getVar(patchtest_patterns.metadata_lic)
            if license == patchtest_patterns.invalid_license:
                no_license = True
                break

        # remove auto.conf line or the file itself
        if open_flag == 'w':
            os.remove(auto_conf)
        else:
            fd = open(auto_conf, 'r')
            lines = fd.readlines()
            fd.close()
            with open(auto_conf, 'w') as fd:
                fd.write(''.join(lines[:-1]))

        if no_license:
            self.fail('Recipe does not have the LICENSE field set.')

    def test_lic_files_chksum_presence(self):
        if not self.added:
            self.skip('No added recipes, skipping test')

        for pn in self.added:
            rd = self.tinfoil.parse_recipe(pn)
            pathname = rd.getVar('FILE')
            # we are not interested in images
            if '/images/' in pathname:
                continue
            lic_files_chksum = rd.getVar(patchtest_patterns.metadata_chksum)
            if rd.getVar(patchtest_patterns.license_var) == patchtest_patterns.closed:
                continue
            if not lic_files_chksum:
                self.fail(
                    "%s is missing in newly added recipe" % patchtest_patterns.metadata_chksum
                )

    def test_lic_files_chksum_modified_not_mentioned(self):
        if not self.modified:
            self.skip('No modified recipes, skipping test')

        for patch in self.patchset:
            # for the moment, we are just interested in metadata
            if patch.path.endswith('.patch'):
                continue
            payload = str(patch)
            if patchtest_patterns.lic_chksum_added.search_string(
                payload
            ) or patchtest_patterns.lic_chksum_removed.search_string(payload):
                # if any patch on the series contain reference on the metadata, fail
                for commit in self.commits:
                    if patchtest_patterns.lictag_re.search_string(commit.commit_message):
                        break
                else:
                    self.fail('LIC_FILES_CHKSUM changed without "License-Update:" tag and description in commit message')

    def test_max_line_length(self):
        for patch in self.patchset:
            # for the moment, we are just interested in metadata
            if patch.path.endswith('.patch'):
                continue
            payload = str(patch)
            for line in payload.splitlines():
                if patchtest_patterns.add_mark.search_string(line):
                    current_line_length = len(line[1:])
                    if current_line_length > patchtest_patterns.patch_max_line_length:
                        self.fail(
                            "Patch line too long (current length %s, maximum is %s)"
                            % (current_line_length, patchtest_patterns.patch_max_line_length),
                            data=[
                                ("Patch", patch.path),
                                ("Line", "%s ..." % line[0:80]),
                            ],
                        )

    def pretest_src_uri_left_files(self):
        # these tests just make sense on patches that can be merged
        if not PatchtestParser.repo.canbemerged:
            self.skip("Patch cannot be merged")
        if not self.modified:
            self.skip('No modified recipes, skipping pretest')

        # get the proper metadata values
        for pn in self.modified:
            # we are not interested in images
            if 'core-image' in pn:
                continue
            rd = self.tinfoil.parse_recipe(pn)
            PatchTestDataStore[
                "%s-%s-%s" % (self.shortid(), patchtest_patterns.metadata_src_uri, pn)
            ] = rd.getVar(patchtest_patterns.metadata_src_uri)

    def test_src_uri_left_files(self):
        # these tests just make sense on patches that can be merged
        if not PatchtestParser.repo.canbemerged:
            self.skip("Patch cannot be merged")
        if not self.modified:
            self.skip('No modified recipes, skipping pretest')

        # get the proper metadata values
        for pn in self.modified:
            # we are not interested in images
            if 'core-image' in pn:
                continue
            rd = self.tinfoil.parse_recipe(pn)
            PatchTestDataStore[
                "%s-%s-%s" % (self.shortid(), patchtest_patterns.metadata_src_uri, pn)
            ] = rd.getVar(patchtest_patterns.metadata_src_uri)

        for pn in self.modified:
            pretest_src_uri = PatchTestDataStore[
                "pre%s-%s-%s" % (self.shortid(), patchtest_patterns.metadata_src_uri, pn)
            ].split()
            test_src_uri = PatchTestDataStore[
                "%s-%s-%s" % (self.shortid(), patchtest_patterns.metadata_src_uri, pn)
            ].split()

            pretest_files = set([os.path.basename(patch) for patch in pretest_src_uri if patch.startswith('file://')])
            test_files    = set([os.path.basename(patch) for patch in test_src_uri    if patch.startswith('file://')])

            # check if files were removed
            if len(test_files) < len(pretest_files):

                # get removals from patchset
                filesremoved_from_patchset = set()
                for patch in self.patchset:
                    if patch.is_removed_file:
                        filesremoved_from_patchset.add(os.path.basename(patch.path))

                # get the deleted files from the SRC_URI
                filesremoved_from_usr_uri = pretest_files - test_files

                # finally, get those patches removed at SRC_URI and not removed from the patchset
                # TODO: we are not taking into account  renames, so test may raise false positives
                not_removed = filesremoved_from_usr_uri - filesremoved_from_patchset
                if not_removed:
                    self.fail('Patches not removed from tree. Remove them and amend the submitted mbox',
                              data=[('Patch', f) for f in not_removed])

    def test_summary_presence(self):
        if not self.added:
            self.skip('No added recipes, skipping test')

        for pn in self.added:
            # we are not interested in images
            if 'core-image' in pn:
                continue
            rd = self.tinfoil.parse_recipe(pn)
            summary = rd.getVar(patchtest_patterns.metadata_summary)

            # "${PN} version ${PN}-${PR}" is the default, so fail if default
            if summary.startswith("%s version" % pn):
                self.fail(
                    "%s is missing in newly added recipe" % patchtest_patterns.metadata_summary
                )

    def test_cve_check_ignore(self):
        # Skip if we neither modified a recipe or target branches are not
        # Nanbield and newer. CVE_CHECK_IGNORE was first deprecated in Nanbield.
        if (
            not self.modified
            or PatchtestParser.repo.patch.branch == "kirkstone"
            or PatchtestParser.repo.patch.branch == "dunfell"
        ):
            self.skip("No modified recipes or older target branch, skipping test")
        for pn in self.modified:
            # we are not interested in images
            if 'core-image' in pn:
                continue
            rd = self.tinfoil.parse_recipe(pn)
            cve_check_ignore = rd.getVar(patchtest_patterns.cve_check_ignore_var)

            if cve_check_ignore is not None:
                self.fail(
                    "%s is deprecated and should be replaced by %s"
                    % (patchtest_patterns.cve_check_ignore_var, patchtest_patterns.cve_status_var)
                )
