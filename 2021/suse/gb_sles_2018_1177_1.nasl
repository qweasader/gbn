# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1177.1");
  script_cve_id("CVE-2017-5754", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-7550", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1177-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181177-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:1177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.
These security issues were fixed:
- CVE-2018-8897: Prevent mishandling of debug exceptions on x86 (XSA-260,
 bsc#1090820)
- Handle HPET timers in IO-APIC mode correctly to prevent malicious or
 buggy HVM guests from causing a hypervisor crash or potentially
 privilege escalation/information leaks (XSA-261, bsc#1090822)
- Prevent unbounded loop, induced by qemu allowing an attacker to
 permanently keep a physical CPU core busy (XSA-262, bsc#1090823)
- CVE-2018-10472: x86 HVM guest OS users (in certain configurations) were
 able to read arbitrary dom0 files via QMP live insertion of a CDROM, in
 conjunction with specifying the target file as the backing file of a
 snapshot (bsc#1089152).
- CVE-2018-10471: x86 PV guest OS users were able to cause a denial of
 service (out-of-bounds zero write and hypervisor crash) via unexpected
 INT 80 processing, because of an incorrect fix for CVE-2017-5754
 (bsc#1089635).
- CVE-2018-7550: The load_multiboot function allowed local guest OS users
 to execute arbitrary code on the host via a mh_load_end_addr value
 greater than mh_bss_end_addr, which triggers an out-of-bounds read or
 write memory access (bsc#1083292).
This non-security issue was fixed:
- bsc#1072834: Prevent unchecked MSR access error
- bsc#1057493: Prevent DomU crashes
- bsc#1086107: Fixed problems with backports for XSA-246 and XSA-247");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_30_k3.12.61_52.125~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.4_30_k3.12.61_52.125~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.4_30~22.65.1", rls:"SLES12.0"))) {
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
