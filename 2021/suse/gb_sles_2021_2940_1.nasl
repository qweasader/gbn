# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2940.1");
  script_cve_id("CVE-2021-29921");
  script_tag(name:"creation_date", value:"2021-09-05 02:21:31 +0000 (Sun, 05 Sep 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-14 18:43:12 +0000 (Fri, 14 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2940-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2940-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212940-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2021:2940-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

CVE-2021-29921: Fixed improper input validation of octal string IP
 addresses (bsc#1185706).

Use versioned python-Sphinx to avoid dependency on other version of
 Python (bsc#1183858).

Stop providing 'python' symbol (bsc#1185588), which means python2
 currently.");

  script_tag(name:"affected", value:"'python39' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.6~4.3.4", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.6~4.3.3", rls:"SLES15.0SP3"))) {
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
