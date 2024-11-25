# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0077");
  script_cve_id("CVE-2013-6885", "CVE-2013-7421", "CVE-2014-0206", "CVE-2014-1739", "CVE-2014-3153", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3917", "CVE-2014-4014", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-5045", "CVE-2014-7970", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8989", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-1421", "CVE-2015-1465");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-03-16 14:19:01 +0000 (Mon, 16 Mar 2015)");

  script_name("Mageia: Security Advisory (MGASA-2015-0077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0077");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0077.html");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.13");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.14");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15224");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.11");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.12");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.13");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.19");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.21");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.22");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.23");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.24");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.27");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.28");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.29");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.30");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.31");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.32");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.8");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.14.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-rt' package(s) announced via the MGASA-2015-0077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-rt update provides as upgrade to upstream 3.14 longterm branch,
currently based on 3.14.32 and fixes the following security issues:

The microcode on AMD 16h 00h through 0Fh processors does not properly handle
the interaction between locked instructions and write-combined memory types,
which allows local users to cause a denial of service (system hang) via a
crafted application, aka the errata 793 issue (CVE-2013-6885)

Array index error in the aio_read_events_ring function in fs/aio.c in
the Linux kernel through 3.15.1 allows local users to obtain sensitive
information from kernel memory via a large head value (CVE-2014-0206).

media-device: fix infoleak in ioctl media_enum_entities()
(CVE-2014-1739)

The futex_requeue function in kernel/futex.c in the Linux kernel through
3.14.5 does not ensure that calls have two different futex addresses,
which allows local users to gain privileges via a crafted FUTEX_REQUEUE
command that facilitates unsafe waiter modification. (CVE-2014-3153)

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux kernel
through 3.16.1 miscalculates the number of pages during the handling of
a mapping failure, which allows guest OS users to (1) cause a denial of
service (host OS memory corruption) or possibly have unspecified other
impact by triggering a large gfn value or (2) cause a denial of service
(host OS memory consumption) by triggering a small gfn value that leads
to permanently pinned pages (CVE-2014-3601).

The WRMSR processing functionality in the KVM subsystem in the Linux
kernel through 3.17.2 does not properly handle the writing of a non-
canonical address to a model-specific register, which allows guest OS
users to cause a denial of service (host OS crash) by leveraging guest
OS privileges, related to the wrmsr_interception function in
arch/x86/kvm/svm.c and the handle_wrmsr function in arch/x86/kvm/vmx.c
(CVE-2014-3610).

Race condition in the __kvm_migrate_pit_timer function in
arch/x86/kvm/i8254.c in the KVM subsystem in the Linux kernel through
3.17.2 allows guest OS users to cause a denial of service (host OS crash)
by leveraging incorrect PIT emulation (CVE-2014-3611).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel through 3.17.2
does not have an exit handler for the INVVPID instruction, which allows
guest OS users to cause a denial of service (guest OS crash) via a crafted
application (CVE-2014-3646).

arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel through
3.17.2 does not properly perform RIP changes, which allows guest OS users
to cause a denial of service (guest OS crash) via a crafted application
(CVE-2014-3647).

kernel/auditsc.c in the Linux kernel through 3.14.5, when
CONFIG_AUDITSYSCALL is enabled with certain syscall rules, allows local
users to obtain potentially sensitive single-bit values from kernel memory
or cause a denial of service (OOPS) via a large value of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-rt' package(s) on Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-3.14.32-0.rt28.1.mga4", rpm:"kernel-rt-3.14.32-0.rt28.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~3.14.32~0.rt28.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-3.14.32-0.rt28.1.mga4", rpm:"kernel-rt-devel-3.14.32-0.rt28.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-latest", rpm:"kernel-rt-devel-latest~3.14.32~0.rt28.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~3.14.32~0.rt28.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-latest", rpm:"kernel-rt-latest~3.14.32~0.rt28.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-3.14.32-0.rt28.1.mga4", rpm:"kernel-rt-source-3.14.32-0.rt28.1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-latest", rpm:"kernel-rt-source-latest~3.14.32~0.rt28.1.mga4", rls:"MAGEIA4"))) {
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
