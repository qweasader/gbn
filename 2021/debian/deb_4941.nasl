# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704941");
  script_cve_id("CVE-2020-36311", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-21 03:00:08 +0000 (Wed, 21 Jul 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:00 +0000 (Thu, 29 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4941-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4941-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4941");
  script_xref(name:"URL", value:"https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4941-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-36311

A flaw was discovered in the KVM subsystem for AMD CPUs, allowing an attacker to cause a denial of service by triggering destruction of a large SEV VM.

CVE-2021-3609

Norbert Slusarek reported a race condition vulnerability in the CAN BCM networking protocol, allowing a local attacker to escalate privileges.

CVE-2021-33909

The Qualys Research Labs discovered a size_t-to-int conversion vulnerability in the Linux kernel's filesystem layer. An unprivileged local attacker able to create, mount, and then delete a deep directory structure whose total path length exceeds 1GB, can take advantage of this flaw for privilege escalation.

Details can be found in the Qualys advisory at [link moved to references]

CVE-2021-34693

Norbert Slusarek discovered an information leak in the CAN BCM networking protocol. A local attacker can take advantage of this flaw to obtain sensitive information from kernel stack memory.

For the stable distribution (buster), these problems have been fixed in version 4.19.194-3.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblockdep-dev", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblockdep4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-4kc-malta", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-5kc-malta", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-686", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-686-pae", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-amd64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-arm64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-armel", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-armhf", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-i386", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-mips", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-mips64el", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-mipsel", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-ppc64el", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-all-s390x", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-amd64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-arm64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-armmp", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-armmp-lpae", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-cloud-amd64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-common", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-common-rt", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-loongson-3", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-marvell", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-octeon", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-powerpc64le", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-rpi", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-rt-686-pae", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-rt-amd64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-rt-arm64", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-rt-armmp", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-17-s390x", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-4kc-malta", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-4kc-malta-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-5kc-malta", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-5kc-malta-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-686-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-686-pae-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-686-pae-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-686-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-amd64-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-amd64-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-arm64-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-arm64-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-armmp", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-armmp-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-armmp-lpae", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-armmp-lpae-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-cloud-amd64-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-cloud-amd64-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-loongson-3", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-loongson-3-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-marvell", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-marvell-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-octeon", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-octeon-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-powerpc64le", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-powerpc64le-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rpi", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rpi-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-686-pae-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-686-pae-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-amd64-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-amd64-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-arm64-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-arm64-unsigned", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-armmp", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-rt-armmp-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-s390x", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-17-s390x-dbg", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-17", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lockdep", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-powerpc64le-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-4kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-5kc-malta-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-armmp-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-loongson-3-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-marvell-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-octeon-di", ver:"4.19.194-3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-17-s390x-di", ver:"4.19.194-3", rls:"DEB10"))) {
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
