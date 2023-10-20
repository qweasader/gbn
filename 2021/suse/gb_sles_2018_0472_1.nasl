# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0472.1");
  script_cve_id("CVE-2017-15595", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566", "CVE-2017-18030", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-5683");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 10:29:00 +0000 (Tue, 30 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0472-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180472-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:0472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.
These security issues were fixed:
- CVE-2017-5753, CVE-2017-5715, CVE-2017-5754: Prevent information leaks
 via side effects of speculative execution, aka 'Spectre' and 'Meltdown'
 attacks (bsc#1074562, bsc#1068032)
- CVE-2017-15595: x86 PV guest OS users were able to cause a DoS
 (unbounded recursion, stack consumption, and hypervisor crash) or
 possibly gain privileges via crafted page-table stacking (bsc#1061081)
- CVE-2017-17566: Prevent PV guest OS users to cause a denial of service
 (host OS crash) or gain host OS privileges in shadow mode by mapping a
 certain auxiliary page (bsc#1070158).
- CVE-2017-17563: Prevent guest OS users to cause a denial of service
 (host OS crash) or gain host OS privileges by leveraging an incorrect
 mask for reference-count overflow checking in shadow mode (bsc#1070159).
- CVE-2017-17564: Prevent guest OS users to cause a denial of service
 (host OS crash) or gain host OS privileges by leveraging incorrect error
 handling for reference counting in shadow mode (bsc#1070160).
- CVE-2017-17565: Prevent PV guest OS users to cause a denial of service
 (host OS crash) if shadow mode and log-dirty mode are in place, because
 of an incorrect assertion related to M2P (bsc#1070163).
- CVE-2018-5683: The vga_draw_text function allowed local OS guest
 privileged users to cause a denial of service (out-of-bounds read and
 QEMU process crash) by leveraging improper memory address validation
 (bsc#1076116).
- CVE-2017-18030: The cirrus_invalidate_region function allowed local OS
 guest privileged users to cause a denial of service (out-of-bounds array
 access and QEMU process crash) via vectors related to negative pitch
 (bsc#1076180).
These non-security issues were fixed:
- bsc#1051729: Prevent invalid symlinks after install of SLES 12 SP2
- bsc#1035442: Increased the value of LIBXL_DESTROY_TIMEOUT from 10 to 100
 seconds. If many domUs shutdown in parallel the backends couldn't keep up
- bsc#1027519: Added several upstream patches");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.4_06~43.24.1", rls:"SLES12.0SP2"))) {
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
