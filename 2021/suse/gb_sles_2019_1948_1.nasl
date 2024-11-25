# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1948.1");
  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-3846");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 19:53:50 +0000 (Tue, 04 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1948-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191948-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 28 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2019:1948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_104 fixes several issues.

The following security issues were fixed:
CVE-2019-11477: Jonathan Looney discovered that the
 TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow
 when handling TCP Selective Acknowledgments (SACKs). A remote attacker
 could use this to cause a denial of service. (bsc#1137586)

CVE-2019-11478: Jonathan Looney discovered that the TCP retransmission
 queue implementation in tcp_fragment could be fragmented when handling
 certain TCP Selective Acknowledgment (SACK) sequences. A remote attacker
 could use this to cause a denial of service. (bsc#1137586)

CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and
 possibly escalate privileges was found in the mwifiex kernel module
 while connecting to a malicious wireless network (bsc#1136424).

This update contains a regression fix for CVE-2019-11477 and CVE-2019-11478 (bsc#1140747).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 28 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_101-default", rpm:"kgraft-patch-4_4_121-92_101-default~4~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_104-default", rpm:"kgraft-patch-4_4_121-92_104-default~4~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_109-default", rpm:"kgraft-patch-4_4_121-92_109-default~4~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_92-default", rpm:"kgraft-patch-4_4_121-92_92-default~8~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_95-default", rpm:"kgraft-patch-4_4_121-92_95-default~7~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_98-default", rpm:"kgraft-patch-4_4_121-92_98-default~6~2.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_140-94_42-default", rpm:"kgraft-patch-4_4_140-94_42-default~10~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_140-94_42-default-debuginfo", rpm:"kgraft-patch-4_4_140-94_42-default-debuginfo~10~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_143-94_47-default", rpm:"kgraft-patch-4_4_143-94_47-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_143-94_47-default-debuginfo", rpm:"kgraft-patch-4_4_143-94_47-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_155-94_50-default", rpm:"kgraft-patch-4_4_155-94_50-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_155-94_50-default-debuginfo", rpm:"kgraft-patch-4_4_155-94_50-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_57-default", rpm:"kgraft-patch-4_4_156-94_57-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_57-default-debuginfo", rpm:"kgraft-patch-4_4_156-94_57-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_61-default", rpm:"kgraft-patch-4_4_156-94_61-default~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_61-default-debuginfo", rpm:"kgraft-patch-4_4_156-94_61-default-debuginfo~7~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_64-default", rpm:"kgraft-patch-4_4_156-94_64-default~6~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_156-94_64-default-debuginfo", rpm:"kgraft-patch-4_4_156-94_64-default-debuginfo~6~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_69-default", rpm:"kgraft-patch-4_4_162-94_69-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_69-default-debuginfo", rpm:"kgraft-patch-4_4_162-94_69-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_72-default", rpm:"kgraft-patch-4_4_162-94_72-default~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_162-94_72-default-debuginfo", rpm:"kgraft-patch-4_4_162-94_72-default-debuginfo~5~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default", rpm:"kgraft-patch-4_4_175-94_79-default~4~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_175-94_79-default-debuginfo", rpm:"kgraft-patch-4_4_175-94_79-default-debuginfo~4~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default", rpm:"kgraft-patch-4_4_176-94_88-default~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_176-94_88-default-debuginfo", rpm:"kgraft-patch-4_4_176-94_88-default-debuginfo~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default", rpm:"kgraft-patch-4_4_178-94_91-default~3~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_178-94_91-default-debuginfo", rpm:"kgraft-patch-4_4_178-94_91-default-debuginfo~3~2.1", rls:"SLES12.0SP3"))) {
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
