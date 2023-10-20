# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2829.1");
  script_cve_id("CVE-2019-10220", "CVE-2019-17133");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2829-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2829-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192829-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 35 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2019:2829-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.74-60_64_118 fixes several issues.

The following security issues were fixed:
CVE-2019-10220: Fixed a relative path escape in the Samba client module
 (bsc#1144903, bsc#1153108).

CVE-2019-17133: Fixed a buffer overflow in cfg80211_mgd_wext_giwessid in
 net/wireless/wext-sme.c caused by long SSID IEs (bsc#1153158).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 35 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_115-default", rpm:"kgraft-patch-3_12_74-60_64_115-default~5~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_115-xen", rpm:"kgraft-patch-3_12_74-60_64_115-xen~5~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_118-default", rpm:"kgraft-patch-3_12_74-60_64_118-default~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_118-xen", rpm:"kgraft-patch-3_12_74-60_64_118-xen~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_121-default", rpm:"kgraft-patch-3_12_74-60_64_121-default~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_121-xen", rpm:"kgraft-patch-3_12_74-60_64_121-xen~3~2.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_101-default", rpm:"kgraft-patch-4_4_121-92_101-default~6~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_104-default", rpm:"kgraft-patch-4_4_121-92_104-default~6~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_109-default", rpm:"kgraft-patch-4_4_121-92_109-default~6~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_114-default", rpm:"kgraft-patch-4_4_121-92_114-default~5~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_117-default", rpm:"kgraft-patch-4_4_121-92_117-default~4~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_120-default", rpm:"kgraft-patch-4_4_121-92_120-default~3~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_98-default", rpm:"kgraft-patch-4_4_121-92_98-default~8~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_64-default", rpm:"kgraft-patch-4_4_156-94_64-default~8~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_64-default-debuginfo", rpm:"kgraft-patch-4_4_156-94_64-default-debuginfo~8~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_69-default", rpm:"kgraft-patch-4_4_162-94_69-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_69-default-debuginfo", rpm:"kgraft-patch-4_4_162-94_69-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_72-default", rpm:"kgraft-patch-4_4_162-94_72-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_72-default-debuginfo", rpm:"kgraft-patch-4_4_162-94_72-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default", rpm:"kgraft-patch-4_4_175-94_79-default~6~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default-debuginfo", rpm:"kgraft-patch-4_4_175-94_79-default-debuginfo~6~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default", rpm:"kgraft-patch-4_4_176-94_88-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default-debuginfo", rpm:"kgraft-patch-4_4_176-94_88-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default", rpm:"kgraft-patch-4_4_178-94_91-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default-debuginfo", rpm:"kgraft-patch-4_4_178-94_91-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_100-default", rpm:"kgraft-patch-4_4_180-94_100-default~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_100-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_100-default-debuginfo~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_103-default", rpm:"kgraft-patch-4_4_180-94_103-default~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_103-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_103-default-debuginfo~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_97-default", rpm:"kgraft-patch-4_4_180-94_97-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_97-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_97-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
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
