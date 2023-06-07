# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.702992");
  script_cve_id("CVE-2014-3534", "CVE-2014-4667", "CVE-2014-4943");
  script_tag(name:"creation_date", value:"2014-07-28 22:00:00 +0000 (Mon, 28 Jul 2014)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2992)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2992");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2992");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2992");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-2992 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation:

CVE-2014-3534

Martin Schwidefsky of IBM discovered that the ptrace subsystem does not properly sanitize the psw mask value. On s390 systems, an unprivileged local user could use this flaw to set address space control bits to kernel space combination and thus gain read/write access to kernel memory.

CVE-2014-4667

Gopal Reddy Kodudula of Nokia Siemens Networks discovered that the sctp_association_free function does not properly manage a certain backlog value, which allows remote attackers to cause a denial of service (socket outage) via a crafted SCTP packet.

CVE-2014-4943

Sasha Levin discovered a flaw in the Linux kernel's point-to-point protocol (PPP) when used with the Layer Two Tunneling Protocol (L2TP). An unprivileged local user could use this flaw for privilege escalation.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.60-1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 3.14.13-2.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ide-core-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ide-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-tape-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-ia64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-powerpc", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-sparc", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-itanium", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mckinley", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc-smp", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-s390x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64-smp", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-itanium", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mckinley", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc-smp", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-dbg", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-tape", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64-smp", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sn-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-kirkwood-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-mx5-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-vexpress-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-s390x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-4kc-malta-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-iop32x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-itanium-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-loongson-2f-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-orion5x-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-powerpc-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sparc64-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-versatile-di", ver:"3.2.60-1+deb7u3", rls:"DEB7"))) {
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
