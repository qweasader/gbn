# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0206");
  script_cve_id("CVE-2014-0049", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-2851");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0206");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0206.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12994");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13080");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13255");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13264");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.12.18");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2014-0206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kernel provides upstream 3.12.18 kernel and fixes the following
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

Integer overflow in the ping_init_sock function in net/ipv4/ping.c in the
Linux kernel through 3.14.1 allows local users to cause a denial of service
(use-after-free and system crash) or possibly gain privileges via a crafted
application that leverages an improperly managed reference counter.
(CVE-2014-2851)

Other, otter fixes in this update:
- switch hugepages back to madvise to fix performance regression (mga#12994)
- enable Intel P-state driver (mga#13080)
- fix r8169 suspend/resume issue (mga#13255)

For upstream merged fixes, read the referenced changelogs:");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.12.18-desktop-1.mga4", rpm:"broadcom-wl-kernel-3.12.18-desktop-1.mga4~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.12.18-desktop586-1.mga4", rpm:"broadcom-wl-kernel-3.12.18-desktop586-1.mga4~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.12.18-server-1.mga4", rpm:"broadcom-wl-kernel-3.12.18-server-1.mga4~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.12.18-desktop-1.mga4", rpm:"fglrx-kernel-3.12.18-desktop-1.mga4~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.12.18-desktop586-1.mga4", rpm:"fglrx-kernel-3.12.18-desktop586-1.mga4~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.12.18-server-1.mga4", rpm:"fglrx-kernel-3.12.18-server-1.mga4~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.12.18-1.mga4", rpm:"kernel-desktop-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.12.18-1.mga4", rpm:"kernel-desktop-devel-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.12.18-1.mga4", rpm:"kernel-desktop586-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.12.18-1.mga4", rpm:"kernel-desktop586-devel-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.12.18-1.mga4", rpm:"kernel-server-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.12.18-1.mga4", rpm:"kernel-server-devel-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.12.18-1.mga4", rpm:"kernel-source-3.12.18-1.mga4~1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.141~28.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~13.251~13.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.12.18-desktop-1.mga4", rpm:"nvidia-current-kernel-3.12.18-desktop-1.mga4~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.12.18-desktop586-1.mga4", rpm:"nvidia-current-kernel-3.12.18-desktop586-1.mga4~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.12.18-server-1.mga4", rpm:"nvidia-current-kernel-3.12.18-server-1.mga4~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~331.49~3.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.12.18-desktop-1.mga4", rpm:"nvidia173-kernel-3.12.18-desktop-1.mga4~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.12.18-desktop586-1.mga4", rpm:"nvidia173-kernel-3.12.18-desktop586-1.mga4~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.12.18-server-1.mga4", rpm:"nvidia173-kernel-3.12.18-server-1.mga4~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.39~14.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.12.18-desktop-1.mga4", rpm:"nvidia304-kernel-3.12.18-desktop-1.mga4~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.12.18-desktop586-1.mga4", rpm:"nvidia304-kernel-3.12.18-desktop586-1.mga4~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.12.18-server-1.mga4", rpm:"nvidia304-kernel-3.12.18-server-1.mga4~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.119~6.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.12.18~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.12.18-desktop-1.mga4", rpm:"vboxadditions-kernel-3.12.18-desktop-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.12.18-desktop586-1.mga4", rpm:"vboxadditions-kernel-3.12.18-desktop586-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.12.18-server-1.mga4", rpm:"vboxadditions-kernel-3.12.18-server-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.12.18-desktop-1.mga4", rpm:"virtualbox-kernel-3.12.18-desktop-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.12.18-desktop586-1.mga4", rpm:"virtualbox-kernel-3.12.18-desktop586-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.12.18-server-1.mga4", rpm:"virtualbox-kernel-3.12.18-server-1.mga4~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.3.10~2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.12.18-desktop-1.mga4", rpm:"xtables-addons-kernel-3.12.18-desktop-1.mga4~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.12.18-desktop586-1.mga4", rpm:"xtables-addons-kernel-3.12.18-desktop586-1.mga4~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.12.18-server-1.mga4", rpm:"xtables-addons-kernel-3.12.18-server-1.mga4~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.3~44.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.3~44.mga4", rls:"MAGEIA4"))) {
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
