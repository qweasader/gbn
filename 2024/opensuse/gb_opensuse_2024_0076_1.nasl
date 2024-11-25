# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833295");
  script_version("2024-10-10T07:25:31+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:47 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for hawk2 (SUSE-SU-2024:0076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0076-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CRNVI5FR75W76MM6FPQQIKVXBLA6QUT2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hawk2'
  package(s) announced via the SUSE-SU-2024:0076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hawk2 fixes the following issues:

  * Fixed HttpOnly secure flag by default (bsc#1216508).

  * Fixed CSRF in errors_controller.rb protection (bsc#1216571).

  Update to version 2.6.4+git.1702030539.5fb7d91b:

  * Fix mime type issue in MS windows (bsc#1215438)

  * Parametrize CORS Access-Control-Allow-Origin header (bsc#1213454)

  * Tests: upgrade tests for ruby3.2 (tumbleweed) (bsc#1215976)

  * Upgrade for ruby3.2 (tumbleweed) (bsc#1215976)

  * Forbid special symbols in the category (bsc#1206217)

  * Fix the sass-rails version on ~5.0 (bsc#1208533)

  * Don't delete the private key if the public key is missing (bsc#1207930)

  * make-sle155-compatible.patch. No bsc, it's for backwards compatibility.

  ##");

  script_tag(name:"affected", value:"'hawk2' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"hawk2", rpm:"hawk2~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debugsource", rpm:"hawk2-debugsource~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debuginfo", rpm:"hawk2-debuginfo~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2", rpm:"hawk2~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debugsource", rpm:"hawk2-debugsource~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debuginfo", rpm:"hawk2-debuginfo~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"hawk2", rpm:"hawk2~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debugsource", rpm:"hawk2-debugsource~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debuginfo", rpm:"hawk2-debuginfo~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2", rpm:"hawk2~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debugsource", rpm:"hawk2-debugsource~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hawk2-debuginfo", rpm:"hawk2-debuginfo~2.6.4+git.1702030539.5fb7d91b~150000.3.39.1", rls:"openSUSELeap15.5"))) {
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