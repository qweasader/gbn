# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0020.1");
  script_cve_id("CVE-2018-18849", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0020-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190020-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:0020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security vulnerabilities fixed:
CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient
 TLB flushing with AMD IOMMUs, which potentially allowed a guest to
 escalate its privileges, may cause a Denial of Service (DoS) affecting
 the entire host, or may be able to access data it is not supposed to
 access. (XSA-275) (bsc#1115040)

CVE-2018-19965: Fixed an issue related to the INVPCID instruction in
 case non-canonical addresses are accessed, which may allow a guest to
 cause Xen to crash, resulting in a Denial of Service (DoS) affecting the
 entire host. (XSA-279) (bsc#1115045)

CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240,
 which conflicted with shadow paging and allowed a guest to cause Xen to
 crash, resulting in a Denial of Service (DoS). (XSA-280) (bsc#1115047)

CVE-2018-19665: Fixed an integer overflow resulting in memory corruption
 in various Bluetooth functions, allowing this to crash qemu process
 resulting in Denial of Service (DoS). (bsc#1117756).

CVE-2018-18849: Fixed an out of bounds memory access in the LSI53C895A
 SCSI host bus adapter emulation, which allowed a user and/or process to
 crash the qemu process resulting in a Denial of Service (DoS).
 (bsc#1114423)

Other bugs fixed:
Fixed an issue related to a domU hang on SLE12-SP3 HV (bsc#1108940)

Fixed an issue with xpti=no-dom0 not working as expected (bsc#1105528)

Fixed an issue with live migrations, which used to fail when spectre is
 enabled on xen boot cmdline (bsc#1116380)

Upstream bug fixes (bsc#1027519)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.6_05~43.45.1", rls:"SLES12.0SP2"))) {
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
