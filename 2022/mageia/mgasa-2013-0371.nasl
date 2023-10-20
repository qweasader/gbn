# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0371");
  script_cve_id("CVE-2013-0343", "CVE-2013-1059", "CVE-2013-2140", "CVE-2013-2147", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2891", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4254", "CVE-2013-4299", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4513", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6381", "CVE-2013-6382", "CVE-2013-6383");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0371");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0371.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11463");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.9");
  script_xref(name:"URL", value:"http://kernelnewbies.org/Linux_3.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.1");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.2");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.3");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.4");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.5");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.6");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.7");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.8");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.9");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.10");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.11");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.12");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.13");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.14");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.15");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.16");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.17");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.18");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.19");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.20");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.21");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.22");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.23");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.24");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'broadcom-wl, btrfs-progs, drakxtools, fglrx, kernel, kernel-firmware, kernel-firmware-nonfree, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, ldetect-lst, libdrm, mesa, nvidia173, nvidia304, nvidia-current, radeon-firmware, x11-driver-video-ati, x11-driver-video-intel, x11-driver-video-nouveau, xtables-addons' package(s) announced via the MGASA-2013-0371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update provides an update to the 3.10 longterm branch,
currently 3.10.24 and fixes the following security issues:

The ipv6_create_tempaddr function in net/ipv6/addrconf.c in the Linux
kernel through 3.10 does not properly handle problems with the generation
of IPv6 temporary addresses, which allows remote attackers to cause a
denial of service (excessive retries and address-generation outage), and
consequently obtain sensitive information, via ICMPv6 Router Advertisement
(RA) messages. (CVE-2013-0343)

net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote
attackers to cause a denial of service (NULL pointer dereference and
system crash) or possibly have unspecified other impact via an auth_reply
message that triggers an attempted build_request operation.
(CVE-2013-1059)

The dispatch_discard_io function in drivers/block/xen-blkback/blkback.c in
the Xen blkback implementation in the Linux kernel before 3.10.5 allows
guest OS users to cause a denial of service (data loss) via filesystem
write operations on a read-only disk that supports the (1)
BLKIF_OP_DISCARD (aka discard or TRIM) or (2) SCSI UNMAP feature.
(CVE-2013-2140)

The HP Smart Array controller disk-array driver and Compaq SMART2
controller disk-array driver in the Linux kernel through 3.9.4 do not
initialize certain data structures, which allows local users to obtain
sensitive information from kernel memory via (1) a crafted IDAGETPCIINFO
command for a /dev/ida device, related to the ida_locked_ioctl function in
drivers/block/cpqarray.c or (2) a crafted CCISS_PASSTHRU32 command for a
/dev/cciss device, related to the cciss_ioctl32_passthru function in
drivers/block/cciss.c. (CVE-2013-2147)

Format string vulnerability in the register_disk function in block/genhd.c
in the Linux kernel through 3.9.4 allows local users to gain privileges by
leveraging root access and writing format string specifiers to
/sys/module/md_mod/parameters/new_array in order to create a crafted
/dev/md device name. (CVE-2013-2851)

Multiple array index errors in drivers/hid/hid-core.c in the Human
Interface Device (HID) subsystem in the Linux kernel through 3.11
allow physically proximate attackers to execute arbitrary code or
cause a denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID (CVE-2013-2888).

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2889).

drivers/hid/hid-steelseries.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_STEELSERIES is
enabled, allows physically proximate attackers to cause a denial of
service (heap-based out-of-bounds write) via a crafted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'broadcom-wl, btrfs-progs, drakxtools, fglrx, kernel, kernel-firmware, kernel-firmware-nonfree, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia173, kmod-nvidia304, kmod-nvidia-current, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons, ldetect-lst, libdrm, mesa, nvidia173, nvidia304, nvidia-current, radeon-firmware, x11-driver-video-ati, x11-driver-video-intel, x11-driver-video-nouveau, xtables-addons' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl", rpm:"broadcom-wl~6.30.223.141~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-common", rpm:"broadcom-wl-common~6.30.223.141~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.24-desktop-2.mga3", rpm:"broadcom-wl-kernel-3.10.24-desktop-2.mga3~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.24-desktop586-2.mga3", rpm:"broadcom-wl-kernel-3.10.24-desktop586-2.mga3~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.10.24-server-2.mga3", rpm:"broadcom-wl-kernel-3.10.24-server-2.mga3~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-progs", rpm:"btrfs-progs~0.20~0.rc1.20130705.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-broadcom-wl", rpm:"dkms-broadcom-wl~6.30.223.141~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-fglrx", rpm:"dkms-fglrx~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia-current", rpm:"dkms-nvidia-current~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia173", rpm:"dkms-nvidia173~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-nvidia304", rpm:"dkms-nvidia304~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-xtables-addons", rpm:"dkms-xtables-addons~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drakx-finish-install", rpm:"drakx-finish-install~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drakxtools", rpm:"drakxtools~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drakxtools-backend", rpm:"drakxtools-backend~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drakxtools-curses", rpm:"drakxtools-curses~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drakxtools-http", rpm:"drakxtools-http~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx", rpm:"fglrx~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-control-center", rpm:"fglrx-control-center~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-devel", rpm:"fglrx-devel~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.24-desktop-2.mga3", rpm:"fglrx-kernel-3.10.24-desktop-2.mga3~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.24-desktop586-2.mga3", rpm:"fglrx-kernel-3.10.24-desktop586-2.mga3~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.10.24-server-2.mga3", rpm:"fglrx-kernel-3.10.24-server-2.mga3~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-opencl", rpm:"fglrx-opencl~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harddrake", rpm:"harddrake~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harddrake-ui", rpm:"harddrake-ui~15.54.1~3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iptaccount", rpm:"iptaccount~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-agn-ucode", rpm:"iwlwifi-agn-ucode~20130624~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.10.24-2.mga3", rpm:"kernel-desktop-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.10.24-2.mga3", rpm:"kernel-desktop-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.10.24-2.mga3", rpm:"kernel-desktop586-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.10.24-2.mga3", rpm:"kernel-desktop586-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20130624~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20130624~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.10.24-2.mga3", rpm:"kernel-server-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.10.24-2.mga3", rpm:"kernel-server-devel-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.10.24-2.mga3", rpm:"kernel-source-3.10.24-2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~6.30.223.141~7.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~13.250.18~5.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia304", rpm:"kmod-nvidia304~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst", rpm:"ldetect-lst~0.1.330~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldetect-lst-devel", rpm:"ldetect-lst-devel~0.1.330~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account-devel", rpm:"lib64account-devel~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account0", rpm:"lib64account0~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64btrfs-devel", rpm:"lib64btrfs-devel~0.20~0.rc1.20130705.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64btrfs0", rpm:"lib64btrfs0~0.20~0.rc1.20130705.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dri-drivers", rpm:"lib64dri-drivers~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1", rpm:"lib64dricore1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1", rpm:"lib64dricore1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1-devel", rpm:"lib64dricore1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dricore1-devel", rpm:"lib64dricore1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm-devel", rpm:"lib64drm-devel~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm-static-devel", rpm:"lib64drm-static-devel~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm2", rpm:"lib64drm2~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm_intel1", rpm:"lib64drm_intel1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm_nouveau2", rpm:"lib64drm_nouveau2~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64drm_radeon1", rpm:"lib64drm_radeon1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1", rpm:"lib64gbm1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gbm1-devel", rpm:"lib64gbm1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0", rpm:"lib64glapi0~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64glapi0-devel", rpm:"lib64glapi0-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kms1", rpm:"lib64kms1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64llvmradeon9.1.7", rpm:"lib64llvmradeon9.1.7~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64llvmradeon9.1.7", rpm:"lib64llvmradeon9.1.7~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1", rpm:"lib64mesaegl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaegl1-devel", rpm:"lib64mesaegl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1", rpm:"lib64mesagl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesagl1-devel", rpm:"lib64mesagl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1", rpm:"lib64mesaglesv1_1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv1_1-devel", rpm:"lib64mesaglesv1_1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2", rpm:"lib64mesaglesv2_2~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaglesv2_2-devel", rpm:"lib64mesaglesv2_2-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1", rpm:"lib64mesaopenvg1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mesaopenvg1-devel", rpm:"lib64mesaopenvg1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa-devel", rpm:"lib64osmesa-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa-devel", rpm:"lib64osmesa-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa8", rpm:"lib64osmesa8~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osmesa8", rpm:"lib64osmesa8~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-nouveau", rpm:"lib64vdpau-driver-nouveau~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-nouveau", rpm:"lib64vdpau-driver-nouveau~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r300", rpm:"lib64vdpau-driver-r300~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r300", rpm:"lib64vdpau-driver-r300~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r600", rpm:"lib64vdpau-driver-r600~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-r600", rpm:"lib64vdpau-driver-r600~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-radeonsi", rpm:"lib64vdpau-driver-radeonsi~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-radeonsi", rpm:"lib64vdpau-driver-radeonsi~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-softpipe", rpm:"lib64vdpau-driver-softpipe~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vdpau-driver-softpipe", rpm:"lib64vdpau-driver-softpipe~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1", rpm:"lib64wayland-egl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wayland-egl1-devel", rpm:"lib64wayland-egl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount-devel", rpm:"libaccount-devel~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount0", rpm:"libaccount0~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbtrfs-devel", rpm:"libbtrfs-devel~0.20~0.rc1.20130705.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbtrfs0", rpm:"libbtrfs0~0.20~0.rc1.20130705.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdri-drivers", rpm:"libdri-drivers~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1", rpm:"libdricore1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1", rpm:"libdricore1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1-devel", rpm:"libdricore1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdricore1-devel", rpm:"libdricore1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm", rpm:"libdrm~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm-common", rpm:"libdrm-common~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm-devel", rpm:"libdrm-devel~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm-static-devel", rpm:"libdrm-static-devel~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm2", rpm:"libdrm2~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm_intel1", rpm:"libdrm_intel1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm_nouveau2", rpm:"libdrm_nouveau2~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdrm_radeon1", rpm:"libdrm_radeon1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-devel", rpm:"libgbm1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0", rpm:"libglapi0~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglapi0-devel", rpm:"libglapi0-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkms1", rpm:"libkms1~2.4.46~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libllvmradeon9.1.7", rpm:"libllvmradeon9.1.7~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libllvmradeon9.1.7", rpm:"libllvmradeon9.1.7~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1", rpm:"libmesaegl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaegl1-devel", rpm:"libmesaegl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1", rpm:"libmesagl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesagl1-devel", rpm:"libmesagl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1", rpm:"libmesaglesv1_1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv1_1-devel", rpm:"libmesaglesv1_1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2", rpm:"libmesaglesv2_2~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaglesv2_2-devel", rpm:"libmesaglesv2_2-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1", rpm:"libmesaopenvg1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmesaopenvg1-devel", rpm:"libmesaopenvg1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa-devel", rpm:"libosmesa-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa-devel", rpm:"libosmesa-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa8", rpm:"libosmesa8~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosmesa8", rpm:"libosmesa8~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-nouveau", rpm:"libvdpau-driver-nouveau~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-nouveau", rpm:"libvdpau-driver-nouveau~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r300", rpm:"libvdpau-driver-r300~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r300", rpm:"libvdpau-driver-r300~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r600", rpm:"libvdpau-driver-r600~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-r600", rpm:"libvdpau-driver-r600~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-radeonsi", rpm:"libvdpau-driver-radeonsi~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-radeonsi", rpm:"libvdpau-driver-radeonsi~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-softpipe", rpm:"libvdpau-driver-softpipe~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau-driver-softpipe", rpm:"libvdpau-driver-softpipe~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1", rpm:"libwayland-egl1~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwayland-egl1-devel", rpm:"libwayland-egl1-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~9.1.7~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-common-devel", rpm:"mesa-common-devel~9.1.7~1.1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current", rpm:"nvidia-current~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-cuda-opencl", rpm:"nvidia-current-cuda-opencl~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-devel", rpm:"nvidia-current-devel~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-doc-html", rpm:"nvidia-current-doc-html~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.24-desktop-2.mga3", rpm:"nvidia-current-kernel-3.10.24-desktop-2.mga3~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.24-desktop586-2.mga3", rpm:"nvidia-current-kernel-3.10.24-desktop586-2.mga3~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.10.24-server-2.mga3", rpm:"nvidia-current-kernel-3.10.24-server-2.mga3~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~319.60~8.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173", rpm:"nvidia173~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-cuda", rpm:"nvidia173-cuda~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-devel", rpm:"nvidia173-devel~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-doc-html", rpm:"nvidia173-doc-html~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.24-desktop-2.mga3", rpm:"nvidia173-kernel-3.10.24-desktop-2.mga3~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.24-desktop586-2.mga3", rpm:"nvidia173-kernel-3.10.24-desktop586-2.mga3~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.10.24-server-2.mga3", rpm:"nvidia173-kernel-3.10.24-server-2.mga3~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.38~24.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304", rpm:"nvidia304~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-cuda-opencl", rpm:"nvidia304-cuda-opencl~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-devel", rpm:"nvidia304-devel~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-doc-html", rpm:"nvidia304-doc-html~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.24-desktop-2.mga3", rpm:"nvidia304-kernel-3.10.24-desktop-2.mga3~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.24-desktop586-2.mga3", rpm:"nvidia304-kernel-3.10.24-desktop586-2.mga3~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-3.10.24-server-2.mga3", rpm:"nvidia304-kernel-3.10.24-server-2.mga3~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop-latest", rpm:"nvidia304-kernel-desktop-latest~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-desktop586-latest", rpm:"nvidia304-kernel-desktop586-latest~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia304-kernel-server-latest", rpm:"nvidia304-kernel-server-latest~304.108~9.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.24~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radeon-firmware", rpm:"radeon-firmware~20130626~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ralink-firmware", rpm:"ralink-firmware~20130624~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtlwifi-firmware", rpm:"rtlwifi-firmware~20130624~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.24-desktop-2.mga3", rpm:"vboxadditions-kernel-3.10.24-desktop-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.24-desktop586-2.mga3", rpm:"vboxadditions-kernel-3.10.24-desktop586-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.24-server-2.mga3", rpm:"vboxadditions-kernel-3.10.24-server-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.24-desktop-2.mga3", rpm:"virtualbox-kernel-3.10.24-desktop-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.24-desktop586-2.mga3", rpm:"virtualbox-kernel-3.10.24-desktop586-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.24-server-2.mga3", rpm:"virtualbox-kernel-3.10.24-server-2.mga3~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.2.16~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-ati", rpm:"x11-driver-video-ati~7.2.0~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-fglrx", rpm:"x11-driver-video-fglrx~13.250.18~0.1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-intel", rpm:"x11-driver-video-intel~2.21.15~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nouveau", rpm:"x11-driver-video-nouveau~1.0.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia-current", rpm:"x11-driver-video-nvidia-current~319.60~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia173", rpm:"x11-driver-video-nvidia173~173.14.38~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-nvidia304", rpm:"x11-driver-video-nvidia304~304.108~2.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~2.3~2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.24-desktop-2.mga3", rpm:"xtables-addons-kernel-3.10.24-desktop-2.mga3~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.24-desktop586-2.mga3", rpm:"xtables-addons-kernel-3.10.24-desktop586-2.mga3~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.10.24-server-2.mga3", rpm:"xtables-addons-kernel-3.10.24-server-2.mga3~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~2.3~8.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-geoip", rpm:"xtables-geoip~2.3~2.mga3", rls:"MAGEIA3"))) {
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
