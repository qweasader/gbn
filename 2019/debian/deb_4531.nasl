# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704531");
  script_cve_id("CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15902");
  script_tag(name:"creation_date", value:"2019-09-26 02:00:16 +0000 (Thu, 26 Sep 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-20 13:01:35 +0000 (Fri, 20 Sep 2019)");

  script_name("Debian: Security Advisory (DSA-4531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4531-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4531-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4531");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-14821

Matt Delco reported a race condition in KVM's coalesced MMIO facility, which could lead to out-of-bounds access in the kernel. A local attacker permitted to access /dev/kvm could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-14835

Peter Pi of Tencent Blade Team discovered a missing bounds check in vhost_net, the network back-end driver for KVM hosts, leading to a buffer overflow when the host begins live migration of a VM. An attacker in control of a VM could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation on the host.

CVE-2019-15117

Hui Peng and Mathias Payer reported a missing bounds check in the usb-audio driver's descriptor parsing code, leading to a buffer over-read. An attacker able to add USB devices could possibly use this to cause a denial of service (crash).

CVE-2019-15118

Hui Peng and Mathias Payer reported unbounded recursion in the usb-audio driver's descriptor parsing code, leading to a stack overflow. An attacker able to add USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. On the amd64 architecture, and on the arm64 architecture in buster, this is mitigated by a guard page on the kernel stack, so that it is only possible to cause a crash.

CVE-2019-15902

Brad Spengler reported that a backporting error reintroduced a spectre-v1 vulnerability in the ptrace subsystem in the ptrace_get_debugreg() function.

For the oldstable distribution (stretch), these problems have been fixed in version 4.9.189-3+deb9u1.

For the stable distribution (buster), these problems have been fixed in version 4.19.67-2+deb10u1.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblockdep-dev", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblockdep4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-4kc-malta", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-5kc-malta", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-686-pae", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-amd64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-arm64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armel", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-armhf", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-i386", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mips64el", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-mipsel", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-ppc64el", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-all-s390x", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-amd64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-arm64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-armmp-lpae", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-cloud-amd64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-common-rt", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-loongson-3", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-marvell", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-octeon", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-powerpc64le", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rpi", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-686-pae", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-amd64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-arm64", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-rt-armmp", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-6-s390x", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-4kc-malta-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-5kc-malta-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-pae-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-686-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-amd64-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-arm64-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-armmp-lpae-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-cloud-amd64-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-loongson-3-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-marvell-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-octeon-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-powerpc64le-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rpi-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-686-pae-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-amd64-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-arm64-unsigned", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-rt-armmp-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-6-s390x-dbg", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-6", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lockdep", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-powerpc64le-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-4kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-5kc-malta-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-armmp-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-loongson-3-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-marvell-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-octeon-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-6-s390x-di", ver:"4.19.67-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"2.0+4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-s390", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-4kc-malta", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-5kc-malta", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-686", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-686-pae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-amd64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-arm64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-armel", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-armhf", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-i386", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-mips", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-mips64el", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-mipsel", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-ppc64el", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-s390x", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-amd64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-arm64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-armmp", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-armmp-lpae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-common", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-common-rt", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-loongson-3", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-marvell", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-octeon", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-powerpc64le", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-rt-686-pae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-rt-amd64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-s390x", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-4kc-malta", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-4kc-malta-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-5kc-malta", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-5kc-malta-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-pae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-pae-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-amd64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-amd64-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-arm64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-arm64-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-lpae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-lpae-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-loongson-3", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-loongson-3-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-marvell", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-marvell-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-octeon", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-octeon-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-powerpc64le", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-powerpc64le-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-686-pae", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-686-pae-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-amd64", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-amd64-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-s390x", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-s390x-dbg", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-11", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-686-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-686-pae-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-amd64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-arm64-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-powerpc64le-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-4kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-5kc-malta-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-armmp-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-loongson-3-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-marvell-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-octeon-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-11-s390x-di", ver:"4.9.189-3+deb9u1", rls:"DEB9"))) {
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
