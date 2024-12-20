# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0038");
  script_cve_id("CVE-2013-4579", "CVE-2014-0038", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1690");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0038");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0038.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12517");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=6077");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.27");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.28");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fglrx, kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2014-0038 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update provides an update to the 3.10 longterm branch,
currently 3.10.28 and fixes the following security issues:

The ath9k_htc_set_bssid_mask function in
drivers/net/wireless/ath/ath9k/htc_drv_main.c in the Linux kernel through
3.12 uses a BSSID masking approach to determine the set of MAC addresses
on which a Wi-Fi device is listening, which allows remote attackers to
discover the original MAC address after spoofing by sending a series of
packets to MAC addresses with certain bit manipulations. (CVE-2013-4579)

Pageexec reported a bug in the Linux kernel's recvmmsg syscall when called
from code using the x32 ABI. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or gain administrator
privileges (CVE-2014-0038)

Faults during task-switch due to unhandled FPU-exceptions allow to
kill processes at random on all affected kernels, resulting in local
DOS in the end. One some architectures, privilege escalation under
non-common circumstances is possible. (CVE-2014-1438)

The hamradio yam_ioctl() code fails to initialise the cmd field of the
struct yamdrv_ioctl_cfg leading to a 4-byte info leak. (CVE-2014-1446)

Linux kernel built with the NetFilter Connection Tracking(NF_CONNTRACK)
support for IRC protocol(NF_NAT_IRC), is vulnerable to an information
leakage flaw. It could occur when communicating over direct
client-to-client IRC connection(/dcc) via a NAT-ed network. Kernel
attempts to mangle IRC TCP packet's content, wherein an uninitialised
'buffer' object is copied to a socket buffer and sent over to the other
end of a connection. (CVE-2014-1690)

It also fixes an issue where some laptops are forced to use
vesa driver & No ACPI (mga#6077)

For other upstream fixes, see the referenced changelogs.

The proprietary fglrx driver has also been updated from Catalyst
13.11-beta6 to Catalyst 13.12 official driver.");

  script_tag(name:"affected", value:"'fglrx, kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.28-desktop-1.mga3", rpm:"broadcom-wl-kernel-3.10.28-desktop-1.mga3~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.28-desktop586-1.mga3", rpm:"broadcom-wl-kernel-3.10.28-desktop586-1.mga3~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.28-server-1.mga3", rpm:"broadcom-wl-kernel-3.10.28-server-1.mga3~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-fglrx", rpm:"dkms-fglrx~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx", rpm:"fglrx~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-control-center", rpm:"fglrx-control-center~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-devel", rpm:"fglrx-devel~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.28-desktop-1.mga3", rpm:"fglrx-kernel-3.10.28-desktop-1.mga3~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.28-desktop586-1.mga3", rpm:"fglrx-kernel-3.10.28-desktop586-1.mga3~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.28-server-1.mga3", rpm:"fglrx-kernel-3.10.28-server-1.mga3~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-opencl", rpm:"fglrx-opencl~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.10.28-1.mga3", rpm:"kernel-desktop-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.10.28-1.mga3", rpm:"kernel-desktop-devel-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.10.28-1.mga3", rpm:"kernel-desktop586-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.10.28-1.mga3", rpm:"kernel-desktop586-devel-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.10.28-1.mga3", rpm:"kernel-server-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.10.28-1.mga3", rpm:"kernel-server-devel-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.10.28-1.mga3", rpm:"kernel-source-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.141~10.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~13.251~3.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.28-desktop-1.mga3", rpm:"nvidia-current-kernel-3.10.28-desktop-1.mga3~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.28-desktop586-1.mga3", rpm:"nvidia-current-kernel-3.10.28-desktop586-1.mga3~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.28-server-1.mga3", rpm:"nvidia-current-kernel-3.10.28-server-1.mga3~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~319.60~11.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.28-desktop-1.mga3", rpm:"nvidia173-kernel-3.10.28-desktop-1.mga3~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.28-desktop586-1.mga3", rpm:"nvidia173-kernel-3.10.28-desktop586-1.mga3~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.28-server-1.mga3", rpm:"nvidia173-kernel-3.10.28-server-1.mga3~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.38~27.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.28-desktop-1.mga3", rpm:"nvidia304-kernel-3.10.28-desktop-1.mga3~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.28-desktop586-1.mga3", rpm:"nvidia304-kernel-3.10.28-desktop586-1.mga3~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.28-server-1.mga3", rpm:"nvidia304-kernel-3.10.28-server-1.mga3~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.108~12.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-desktop-1.mga3", rpm:"vboxadditions-kernel-3.10.28-desktop-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-desktop586-1.mga3", rpm:"vboxadditions-kernel-3.10.28-desktop586-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-server-1.mga3", rpm:"vboxadditions-kernel-3.10.28-server-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-desktop-1.mga3", rpm:"virtualbox-kernel-3.10.28-desktop-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-desktop586-1.mga3", rpm:"virtualbox-kernel-3.10.28-desktop586-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-server-1.mga3", rpm:"virtualbox-kernel-3.10.28-server-1.mga3~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.2.16~7.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-fglrx", rpm:"x11-driver-video-fglrx~13.251~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.28-desktop-1.mga3", rpm:"xtables-addons-kernel-3.10.28-desktop-1.mga3~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.28-desktop586-1.mga3", rpm:"xtables-addons-kernel-3.10.28-desktop586-1.mga3~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.28-server-1.mga3", rpm:"xtables-addons-kernel-3.10.28-server-1.mga3~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.3~11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.3~11.mga3", rls:"MAGEIA3"))) {
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
