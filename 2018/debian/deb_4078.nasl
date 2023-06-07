# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704078");
  script_cve_id("CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-03 23:00:00 +0000 (Wed, 03 Jan 2018)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");

  script_name("Debian: Security Advisory (DSA-4078)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4078");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4078");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4078 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple researchers have discovered a vulnerability in Intel processors, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Meltdown and is addressed in the Linux kernel for the Intel x86-64 architecture by a patch set named Kernel Page Table Isolation, enforcing a near complete separation of the kernel and userspace address maps and preventing the attack. This solution might have a performance impact, and can be disabled at boot time by passing pti=off to the kernel command line.

We also identified a regression for ancient userspaces using the vsyscall interface, for example chroot and containers using (e)glibc 2.13 and older, including those based on Debian 7 or RHEL/CentOS 6. This regression will be fixed in a later update.

The other vulnerabilities (named Spectre) published at the same time are not addressed in this update and will be fixed in a later update.

For the oldstable distribution (jessie), this problem will be fixed in a separate update.

For the stable distribution (stretch), this problem has been fixed in version 4.9.65-3+deb9u2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"2.0+4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-s390", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-4kc-malta", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-5kc-malta", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-686-pae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-686", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-amd64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-arm64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-armel", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-armhf", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-i386", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mips", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mips64el", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-mipsel", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-ppc64el", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all-s390x", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-all", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-amd64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-arm64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-armmp-lpae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-armmp", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-common-rt", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-common", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-loongson-3", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-marvell", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-octeon", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-powerpc64le", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-rt-686-pae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-rt-amd64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-5-s390x", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-4kc-malta-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-4kc-malta", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-5kc-malta-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-5kc-malta", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-pae-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686-pae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-686", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-amd64-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-amd64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-arm64-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-arm64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-lpae-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp-lpae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-armmp", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-loongson-3-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-loongson-3", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-marvell-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-marvell", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-octeon-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-octeon", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-powerpc64le-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-powerpc64le", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-686-pae-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-686-pae", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-amd64-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-rt-amd64", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-s390x-dbg", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-5-s390x", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-5", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-686-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-686-pae-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-amd64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-arm64-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-powerpc64le-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-4kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-5kc-malta-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-armmp-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-loongson-3-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-marvell-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-octeon-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.9.0-5-s390x-di", ver:"4.9.65-3+deb9u2", rls:"DEB9"))) {
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
