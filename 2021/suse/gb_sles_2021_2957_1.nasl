# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2957.1");
  script_cve_id("CVE-2021-0089", "CVE-2021-20255", "CVE-2021-28690", "CVE-2021-28692", "CVE-2021-28694", "CVE-2021-28695", "CVE-2021-28696", "CVE-2021-28697", "CVE-2021-28698", "CVE-2021-28699", "CVE-2021-3592", "CVE-2021-3594", "CVE-2021-3595");
  script_tag(name:"creation_date", value:"2021-09-07 02:20:52 +0000 (Tue, 07 Sep 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-01 18:54:30 +0000 (Wed, 01 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2957-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2957-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212957-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2021:2957-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

CVE-2021-3594: slirp: invalid pointer initialization may lead to
 information disclosure (udp)(bsc#1187378).

CVE-2021-3595: slirp: invalid pointer initialization may lead to
 information disclosure (tftp)(bsc#1187376).

CVE-2021-28698: long running loops in grant table handling
 (XSA-380)(bsc#1189378).

CVE-2021-28699: inadequate grant-v2 status frames array bounds check
 (XSA-382)(bsc#1189380).

CVE-2021-20255: Fixed stack overflow via infinite recursion in eepro100
 (bsc#1182654)

CVE-2021-28690: xen: x86: TSX Async Abort protections not restored after
 S3 (bsc#1186434)

CVE-2021-28692: xen: inappropriate x86 IOMMU timeout detection /
 handling (bsc#1186429)

CVE-2021-28694,CVE-2021-28695,CVE-2021-28696: IOMMU page mapping issues
 on x86 (XSA-378)(bsc#1189373).

CVE-2021-0089: xen: Speculative Code Store Bypass (bsc#1186433)

CVE-2021-28697: grant table v2 status pages may remain accessible after
 de-allocation (XSA-379)(bsc#1189376).

CVE-2021-3592: slirp: invalid pointer initialization may lead to
 information disclosure (bootp)(bsc#1187369).

Prevent superpage allocation in the LAPIC and ACPI_INFO range
 (bsc#1189882).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.9.4_20~3.91.1", rls:"SLES12.0SP3"))) {
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
