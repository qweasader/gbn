# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856334");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2024-6104");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-07-28 04:00:23 +0000 (Sun, 28 Jul 2024)");
  script_name("openSUSE: Security Advisory for gh (openSUSE-SU-2024:0227-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0227-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G2COZIDAEHXSE2NGBIJOMDBA64FCPZOP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gh'
  package(s) announced via the openSUSE-SU-2024:0227-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gh fixes the following issues:

     Update to version 2.53.0:

  * CVE-2024-6104: gh: hashicorp/go-retryablehttp: url might write sensitive
       information to log file (boo#1227035)

  * Rename package directory and files

  * Rename package name to `update_branch`

  * Rename `gh pr update` to `gh pr update-branch`

  * Add test case for merge conflict error

  * Handle merge conflict error

  * Return error if PR is not mergeable

  * Replace literals with consts for `Mergeable` field values

  * Add separate type for `PullRequest.Mergeable` field

  * Remove unused flag

  * Print message on stdout instead of stderr

  * Raise error if editor is used in non-tty mode

  * Add tests for JSON field support on issue and pr view commands

  * docs: Update documentation for `gh repo create` to clarify owner

  * Ensure PR does not panic when stateReason is requested

  * Add `createdAt` field to tests

  * Add `createdAt` field to `Variable` type

  * Add test for exporting as JSON

  * Add test for JSON output

  * Only populate selected repo information for JSON output

  * Add test to verify JSON exporter gets set

  * Add `--json` option support

  * Use `Variable` type defined in `shared` package

  * Add tests for JSON output

  * Move `Variable` type and `PopulateSelectedRepositoryInformation` func to
       shared

  * Fix query parameter name

  * Update tests to account for ref comparison step

  * Improve query variable names

  * Check if PR branch is already up-to-date

  * Add `ComparePullRequestBaseBranchWith` function

  * Run `go mod tidy`

  * Add test to verify `--repo` requires non-empty selector

  * Require non-empty selector when `--repo` override is used

  * Run `go mod tidy`

  * Register `update` command

  * Add tests for `pr update` command

  * Add `pr update` command

  * Add `UpdatePullRequestBranch` method

  * Upgrade `shurcooL/githubv4`

     Update to version 2.52.0:

  * Attestation Verification - Buffer Fix

  * Remove beta note from attestation top level command

  * Removed beta note from `gh at download`.

  * Removed beta note from `gh at verify`, clarified reusable workflows use
       case.

  * add `-a` flag to `gh run list`");

  script_tag(name:"affected", value:"'gh' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gh", rpm:"gh~2.53.0~bp155.2.12.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-bash-completion", rpm:"gh-bash-completion~2.53.0~bp155.2.12.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-fish-completion", rpm:"gh-fish-completion~2.53.0~bp155.2.12.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-zsh-completion", rpm:"gh-zsh-completion~2.53.0~bp155.2.12.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
