# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3252.2");
  script_cve_id("CVE-2022-27404", "CVE-2022-27405", "CVE-2022-27406");
  script_tag(name:"creation_date", value:"2022-09-23 04:48:10 +0000 (Fri, 23 Sep 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-03 19:34:00 +0000 (Tue, 03 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3252-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3252-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223252-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2022:3252-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freetype2 fixes the following issues:

CVE-2022-27404 Fixed a segmentation fault via a crafted typeface
 (bsc#1198830).

CVE-2022-27405 Fixed a buffer overflow via a crafted typeface
 (bsc#1198832).

CVE-2022-27406 Fixed a segmentation fault via a crafted typeface
 (bsc#1198823).

Non-security fixes:

Updated to version 2.10.4");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.10.4~150000.4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.10.4~150000.4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.10.4~150000.4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.10.4~150000.4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit-debuginfo", rpm:"libfreetype6-32bit-debuginfo~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.10.4~150000.4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftdump", rpm:"ftdump~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit-debuginfo", rpm:"libfreetype6-32bit-debuginfo~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.10.4~150000.4.12.1", rls:"SLES15.0SP2"))) {
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
