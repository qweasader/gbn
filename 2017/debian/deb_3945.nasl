# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703945");
  script_cve_id("CVE-2014-9940", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-7346", "CVE-2017-7482", "CVE-2017-7533", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2017-08-16 22:00:00 +0000 (Wed, 16 Aug 2017)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-28 22:06:00 +0000 (Thu, 28 Sep 2023)");

  script_name("Debian: Security Advisory (DSA-3945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3945-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3945-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3945");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2014-9940

A use-after-free flaw in the voltage and current regulator driver could allow a local user to cause a denial of service or potentially escalate privileges.

CVE-2017-7346

Li Qiang discovered that the DRM driver for VMware virtual GPUs does not properly check user-controlled values in the vmw_surface_define_ioctl() functions for upper limits. A local user can take advantage of this flaw to cause a denial of service.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does not properly verify metadata, leading to information disclosure, denial of service or potentially execution of arbitrary code.

CVE-2017-7533

Fan Wu and Shixiong Zhao discovered a race condition between inotify events and VFS rename operations allowing an unprivileged local attacker to cause a denial of service or escalate privileges.

CVE-2017-7541

A buffer overflow flaw in the Broadcom IEEE802.11n PCIe SoftMAC WLAN driver could allow a local user to cause kernel memory corruption, leading to a denial of service or potentially privilege escalation.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt() function was found allowing a local attacker with privileges to open raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism, allowing a local attacker with access to /dev/mem to obtain sensitive information or potentially execute arbitrary code.

CVE-2017-9605

Murray McAllister discovered that the DRM driver for VMware virtual GPUs does not properly initialize memory, potentially allowing a local attacker to obtain sensitive information from uninitialized kernel memory via a crafted ioctl call.

CVE-2017-10911

/ XSA-216

Anthony Perard of Citrix discovered an information leak flaw in Xen blkif response handling, allowing a malicious unprivileged guest to obtain sensitive information from the host or other guests.

CVE-2017-11176

It was discovered that the mq_notify() function does not set the sock pointer to NULL upon entry into the retry logic. An attacker can take advantage of this flaw during a userspace close of a Netlink socket to cause a denial of service or potentially cause other impact.

CVE-2017-1000363

Roee Hay reported that the lp driver does not properly bounds-check passed arguments, allowing a local attacker with write access to the kernel command line arguments to execute arbitrary code.

CVE-2017-1000365

It was discovered that argument and environment pointers are not taken properly into account to the imposed size restrictions on arguments and environmental strings passed through RLIMIT_STACK/RLIMIT_INFINITY. A local attacker can take ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-s390", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-x86", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-4kc-malta", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-586", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-5kc-malta", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-686-pae", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-amd64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-arm64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armel", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armhf", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-i386", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mips", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mipsel", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-powerpc", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-ppc64el", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-s390x", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-amd64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-arm64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp-lpae", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-common", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-ixp4xx", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-kirkwood", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2e", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2f", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-3", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-octeon", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-orion5x", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc-smp", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64le", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r4k-ip22", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r5k-ip32", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-s390x", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-sb1-bcm91250a", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-versatile", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-4kc-malta", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-586", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-5kc-malta", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae-dbg", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64-dbg", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64-dbg", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp-lpae", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-ixp4xx", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-kirkwood", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2e", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2f", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-3", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-octeon", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-orion5x", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc-smp", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64le", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r4k-ip22", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r5k-ip32", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x-dbg", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-sb1-bcm91250a", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-versatile", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-4", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-kirkwood-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-4-amd64", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-586-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-686-pae-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-amd64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-arm64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc64-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-powerpc64le-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-s390x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-4kc-malta-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-armmp-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-2e-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-2f-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-loongson-3-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-octeon-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-orion5x-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-powerpc-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-r4k-ip22-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-r5k-ip32-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-sb1-bcm91250a-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.16.0-4-versatile-di", ver:"3.16.43-2+deb8u3", rls:"DEB8"))) {
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
