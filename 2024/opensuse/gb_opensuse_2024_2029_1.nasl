# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856217");
  script_version("2024-10-25T15:39:56+0000");
  script_cve_id("CVE-2024-5206");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-25 15:39:56 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-24 19:48:31 +0000 (Thu, 24 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:00:31 +0000 (Sat, 15 Jun 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:2029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2029-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RRNRD64XAZJHFLB6MHKCGUBBVTIA3E7V");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:2029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-scikit-learn fixes the following issues:

  - CVE-2024-5206: Fixed a possible sensitive data leak in TfidfVectorizer.
  (bsc#1226185)

  ##");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn-debuginfo", rpm:"python3-scikit-learn-debuginfo~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-scikit-learn", rpm:"python3-scikit-learn~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-scikit-learn-debugsource", rpm:"python-scikit-learn-debugsource~0.23.2~150300.3.3.1", rls:"openSUSELeap15.3"))) {
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