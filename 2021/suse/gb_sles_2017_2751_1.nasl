# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2751.1");
  script_cve_id("CVE-2017-5526");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 19:21:00 +0000 (Tue, 10 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2751-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2751-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172751-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:2751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues:
These security issues were fixed:
- CVE-2017-5526: The ES1370 audio device emulation support was vulnerable
 to a memory leakage issue allowing a privileged user inside the guest to
 cause a DoS and/or potentially crash the Qemu process on the host
 (bsc#1059777)
- bsc#1061084: Missing cleanup in the page type system allowed a malicious
 or buggy PV guest to cause DoS (XSA-242)
- bsc#1061086: A problem in the shadow pagetable code allowed a malicious
 or buggy HVM guest to cause DoS or cause hypervisor memory corruption
 potentially allowing the guest to escalate its privilege (XSA-243)
- bsc#1061087: Problematic handling of the selector fields in the
 Interrupt Descriptor Table (IDT) allowed a malicious or buggy x86 PV
 guest to escalate its privileges or cause DoS (XSA-244)
- bsc#1061077 Missing checks in the handling of DMOPs allowed malicious or
 buggy stub domain kernels or tool stacks otherwise living outside of
 Domain0 to cause a DoS (XSA-238)
- bsc#1061080: Intercepted I/O write operations with less than a full
 machine word's worth of data were not properly handled, which allowed a
 malicious unprivileged x86 HVM guest to obtain sensitive information
 from the host or
 other guests (XSA-239)
- bsc#1061081: In certain configurations of linear page tables a stack
 overflow might have occurred that allowed a malicious or buggy PV guest
 to cause DoS and potentially privilege escalation and information leaks
 (XSA-240)
- bsc#1061082: Under certain conditions x86 PV guests could have caused
 the hypervisor to miss a necessary TLB flush for a page. This allowed a
 malicious x86 PV guest to access all of system memory, allowing for
 privilege escalation, DoS, and information leaks (XSA-241)
- bsc#1061076: Multiple issues existed with the setup of PCI MSI
 interrupts that allowed a malicious or buggy guest to cause DoS and
 potentially privilege escalation and information leaks (XSA-237)
- bsc#1055321: When dealing with the grant map space of add-to-physmap
 operations, ARM specific code failed to release a lock. This allowed a
 malicious guest administrator to cause DoS (XSA-235)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.9.0_14~3.18.1", rls:"SLES12.0SP3"))) {
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
