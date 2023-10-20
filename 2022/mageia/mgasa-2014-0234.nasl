# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0234");
  script_cve_id("CVE-2014-0049", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0155", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2851");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0234.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13080");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13255");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13266");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.19");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2014-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel-tmb provides upstream 3.12.20 kernel and fixes the following
security issues:

Buffer overflow in the complete_emulated_mmio function in arch/x86/kvm/
x86.c in the Linux kernel before 3.13.6 allows guest OS users to execute
arbitrary code on the host OS by leveraging a loop that triggers an
invalid memory copy affecting certain cancel_work_item data.
(CVE-2014-0049)

The get_rx_bufs function in drivers/vhost/net.c in the vhost-net subsystem
in the Linux kernel package before 2.6.32-431.11.2 on Red Hat Enterprise
Linux (RHEL) 6 does not properly handle vhost_get_vq_desc errors, which
allows guest OS users to cause a denial of service (host OS crash) via
unspecified vectors. (CVE-2014-0055)

The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel through
3.13.5 does not properly handle uncached write operations that copy fewer
than the requested number of bytes, which allows local users to obtain
sensitive information from kernel memory, cause a denial of service
(memory corruption and system crash), or possibly gain privileges via a
writev system call with a crafted pointer. (CVE-2014-0069)

drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable
buffers are disabled, does not properly validate packet lengths, which
allows guest OS users to cause a denial of service (memory corruption and
host OS crash) or possibly gain privileges on the host OS via crafted
packets, related to the handle_rx and get_rx_bufs functions.
(CVE-2014-0077)

The ioapic_deliver function in virt/kvm/ioapic.c in the Linux kernel
through 3.14.1 does not properly validate the kvm_irq_delivery_to_apic
return value, which allows guest OS users to cause a denial of service
(host OS crash) via a crafted entry in the redirection table of an I/O
APIC. NOTE: the affected code was moved to the ioapic_service function
before the vulnerability was announced. (CVE-2014-0155)

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the
'LECHO & !OPOST' case, which allows local users to cause a denial of
service (memory corruption and system crash) or gain privileges by
triggering a race condition involving read and write operations with
long strings. (CVE-2014-0196)

The raw_cmd_copyin function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly handle error conditions during
processing of an FDRAWCMD ioctl call, which allows local users to trigger
kfree operations and gain privileges by leveraging write access to a
/dev/fd device. (CVE-2014-1737)

The raw_cmd_copyout function in drivers/block/floppy.c in the Linux
kernel through 3.14.3 does not properly restrict access to certain
pointers during processing of an FDRAWCMD ioctl call, which allows
local users to obtain sensitive information from kernel heap memory
by leveraging write access to a /dev/fd device. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-3.12.20-1.mga4", rpm:"kernel-tmb-desktop-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-3.12.20-1.mga4", rpm:"kernel-tmb-desktop-devel-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-3.12.20-1.mga4", rpm:"kernel-tmb-desktop586-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-3.12.20-1.mga4", rpm:"kernel-tmb-desktop586-devel-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-devel-latest", rpm:"kernel-tmb-desktop586-devel-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop586-latest", rpm:"kernel-tmb-desktop586-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-3.12.20-1.mga4", rpm:"kernel-tmb-laptop-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-3.12.20-1.mga4", rpm:"kernel-tmb-laptop-devel-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-devel-latest", rpm:"kernel-tmb-laptop-devel-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-laptop-latest", rpm:"kernel-tmb-laptop-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-3.12.20-1.mga4", rpm:"kernel-tmb-server-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-3.12.20-1.mga4", rpm:"kernel-tmb-server-devel-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-devel-latest", rpm:"kernel-tmb-server-devel-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-server-latest", rpm:"kernel-tmb-server-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-3.12.20-1.mga4", rpm:"kernel-tmb-source-3.12.20-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~3.12.20~1.mga4", rls:"MAGEIA4"))) {
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
