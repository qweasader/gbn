# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0273");
  script_cve_id("CVE-2014-0181", "CVE-2014-1739", "CVE-2014-3153", "CVE-2014-3917", "CVE-2014-4014");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 12:17:50 +0000 (Tue, 02 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2014-0273)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0273");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0273.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13487");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.41");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.42");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.43");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.44");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2014-0273 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel has been updated to the upstream 3.10.44 longterm kernel,
and fixes the following security issues:

The Netlink implementation in the Linux kernel through 3.14.1 does not
provide a mechanism for authorizing socket operations based on the
opener of a socket, which allows local users to bypass intended access
restrictions and modify network configurations by using a Netlink socket
for the (1) stdout or (2) stderr of a setuid program. (CVE-2014-0181)

media-device: fix infoleak in ioctl media_enum_entities()
(CVE-2014-1739)

The futex_requeue function in kernel/futex.c in the Linux kernel through
3.14.5 does not ensure that calls have two different futex addresses,
which allows local users to gain privileges via a crafted FUTEX_REQUEUE
command that facilitates unsafe waiter modification. (CVE-2014-3153)

kernel/auditsc.c in the Linux kernel through 3.14.5, when AUDITSYSCALL
is enabled with certain syscall rules, allows local users to obtain
potentially sensitive single-bit values from kernel memory or cause a
denial of service (OOPS) via a large value of a syscall number.
(CVE-2014-3917)

Andy Lutomirski has reported a vulnerability in Linux Kernel, which can
be exploited by malicious, local users to gain escalated privileges.
The vulnerability is caused due to an error related to checking Inode
capabilities, which can be exploited to conduct certain actions with
escalated privileges.
Successful exploitation requires a kernel built with user namespaces
(USER_NS) enabled. (CVE-2014-4014)

For other changes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.44-desktop-1.mga3", rpm:"broadcom-wl-kernel-3.10.44-desktop-1.mga3~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.44-desktop586-1.mga3", rpm:"broadcom-wl-kernel-3.10.44-desktop586-1.mga3~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.44-server-1.mga3", rpm:"broadcom-wl-kernel-3.10.44-server-1.mga3~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.44-desktop-1.mga3", rpm:"fglrx-kernel-3.10.44-desktop-1.mga3~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.44-desktop586-1.mga3", rpm:"fglrx-kernel-3.10.44-desktop586-1.mga3~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.44-server-1.mga3", rpm:"fglrx-kernel-3.10.44-server-1.mga3~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.10.44-1.mga3", rpm:"kernel-desktop-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.10.44-1.mga3", rpm:"kernel-desktop-devel-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.10.44-1.mga3", rpm:"kernel-desktop586-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.10.44-1.mga3", rpm:"kernel-desktop586-devel-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.10.44-1.mga3", rpm:"kernel-server-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.10.44-1.mga3", rpm:"kernel-server-devel-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.10.44-1.mga3", rpm:"kernel-source-3.10.44-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.141~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~13.251~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.44-desktop-1.mga3", rpm:"nvidia-current-kernel-3.10.44-desktop-1.mga3~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.44-desktop586-1.mga3", rpm:"nvidia-current-kernel-3.10.44-desktop586-1.mga3~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.44-server-1.mga3", rpm:"nvidia-current-kernel-3.10.44-server-1.mga3~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~319.60~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.44-desktop-1.mga3", rpm:"nvidia173-kernel-3.10.44-desktop-1.mga3~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.44-desktop586-1.mga3", rpm:"nvidia173-kernel-3.10.44-desktop586-1.mga3~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.44-server-1.mga3", rpm:"nvidia173-kernel-3.10.44-server-1.mga3~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.38~32.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.44-desktop-1.mga3", rpm:"nvidia304-kernel-3.10.44-desktop-1.mga3~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.44-desktop586-1.mga3", rpm:"nvidia304-kernel-3.10.44-desktop586-1.mga3~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.44-server-1.mga3", rpm:"nvidia304-kernel-3.10.44-server-1.mga3~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.108~17.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.44~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.44-desktop-1.mga3", rpm:"vboxadditions-kernel-3.10.44-desktop-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.44-desktop586-1.mga3", rpm:"vboxadditions-kernel-3.10.44-desktop586-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.44-server-1.mga3", rpm:"vboxadditions-kernel-3.10.44-server-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.44-desktop-1.mga3", rpm:"virtualbox-kernel-3.10.44-desktop-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.44-desktop586-1.mga3", rpm:"virtualbox-kernel-3.10.44-desktop586-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.44-server-1.mga3", rpm:"virtualbox-kernel-3.10.44-server-1.mga3~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.3.10~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.44-desktop-1.mga3", rpm:"xtables-addons-kernel-3.10.44-desktop-1.mga3~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.44-desktop586-1.mga3", rpm:"xtables-addons-kernel-3.10.44-desktop586-1.mga3~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.44-server-1.mga3", rpm:"xtables-addons-kernel-3.10.44-server-1.mga3~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.3~17.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.3~17.mga3", rls:"MAGEIA3"))) {
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
