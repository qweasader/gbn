# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856114");
  script_version("2024-05-16T05:05:35+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-07 01:00:26 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for skopeo (SUSE-SU-2024:1497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1497-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DJKIOKQKBDI6VZW2V3G2YQAGSTIHPEIH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'skopeo'
  package(s) announced via the SUSE-SU-2024:1497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for skopeo fixes the following issues:

  * Update to version 1.14.2:

  * [release-1.14] Bump Skopeo to v1.14.2

  * [release-1.14] Bump c/image to v5.29.2, c/common to v0.57.3 (fixes
      bsc#1219563)

  * Update to version 1.14.1:

  * Bump to v1.14.1

  * fix(deps): update module github.com/containers/common to v0.57.2

  * fix(deps): update module github.com/containers/image/v5 to v5.29.1

  * chore(deps): update dependency containers/automation_images to v20240102

  * Fix libsubid detection

  * fix(deps): update module golang.org/x/term to v0.16.0

  * fix(deps): update golang.org/x/exp digest to 02704c9

  * chore(deps): update dependency containers/automation_images to v20231208

  * [skip-ci] Update actions/stale action to v9

  * fix(deps): update module github.com/containers/common to v0.57.1

  * fix(deps): update golang.org/x/exp digest to 6522937

  * DOCS: add Gentoo in install.md

  * DOCS: Update to add Arch Linux in install.md

  * fix(deps): update module golang.org/x/term to v0.15.0

  * Bump to v1.14.1-dev

  * Update to version 1.14.0:

  * Bump to v1.14.0

  * fix(deps): update module github.com/containers/common to v0.57.0

  * chore(deps): update dependency containers/automation_images to v20231116

  * fix(deps): update module github.com/containers/image/v5 to v5.29.0

  * Add documentation and smoke tests for the new --compat-auth-file options

  * Update c/image and c/common to latest

  * fix(deps): update module github.com/containers/storage to v1.51.0

  * fix(deps): update module golang.org/x/term to v0.14.0

  * fix(deps): update module github.com/spf13/cobra to v1.8.0

  * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.2

  * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.1

  * fix(deps): update github.com/containers/common digest to 3e5caa0

  * chore(deps): update module google.golang.org/grpc to v1.57.1 [security]

  * fix(deps): update module github.com/containers/ocicrypt to v1.1.9

  * Update github.com/klauspost/compress to v1.17.2

  * chore(deps): update module github.com/docker/docker to v24.0.7+incompatible
      [security]

  * Fix ENTRYPOINT documentation, drop others.

  * Remove unused environment variables in Cirrus

  * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.0

  * chore(deps): update dependency containers/automation_images to v20231004

  * chore(deps): update module golang.org/x/net to v0.17.0 [security]

  * copy: Note support for `zstd:chunked`

  * fix(deps): update module golang.org/x/term to v0.13. ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'skopeo' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-zsh-completion", rpm:"skopeo-zsh-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-bash-completion", rpm:"skopeo-bash-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-fish-completion", rpm:"skopeo-fish-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-zsh-completion", rpm:"skopeo-zsh-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-bash-completion", rpm:"skopeo-bash-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-fish-completion", rpm:"skopeo-fish-completion~1.14.2~150300.11.8.1", rls:"openSUSELeap15.3"))) {
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