# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856346");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2022-48560", "CVE-2023-27043", "CVE-2023-52425", "CVE-2024-0450");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:31 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1862-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3YSE4IOP4ISWHX3ARM75WVNBEW5HPEM3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1862-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python fixes the following issues:

  * CVE-2023-52425: Fixed using the system libexpat (bsc#1219559).

  * CVE-2023-27043: Modified fix for unicode string handling in
      email.utils.parseaddr() (bsc#1222537).

  * CVE-2022-48560: Fixed use-after-free in Python via heappushpop in heapq
      (bsc#1214675).

  * CVE-2024-0450: Detect the vulnerability of the 'quoted-overlap' zipbomb
      (bsc#1221854).

  Bug fixes:

  * Switch off tests. ONLY FOR FACTORY!!! (bsc#1219306).

  * Build with -std=gnu89 to build correctly with gcc14 (bsc#1220970).

  * Switch from %patchN style to the %patch -P N one.

  ##");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-idle", rpm:"python-idle~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-demo", rpm:"python-demo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit", rpm:"python-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit-debuginfo", rpm:"python-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit-debuginfo", rpm:"python-base-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit", rpm:"python-base-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit-debuginfo", rpm:"libpython2_7-1_0-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit", rpm:"libpython2_7-1_0-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc", rpm:"python-doc~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc-pdf", rpm:"python-doc-pdf~2.7.18~150000.65.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-idle", rpm:"python-idle~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-demo", rpm:"python-demo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit", rpm:"python-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit-debuginfo", rpm:"python-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit-debuginfo", rpm:"python-base-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit", rpm:"python-base-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit-debuginfo", rpm:"libpython2_7-1_0-32bit-debuginfo~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit", rpm:"libpython2_7-1_0-32bit~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc", rpm:"python-doc~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc-pdf", rpm:"python-doc-pdf~2.7.18~150000.65.1", rls:"openSUSELeap15.5"))) {
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
