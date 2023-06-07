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
  script_oid("1.3.6.1.4.1.25623.1.0.841998");
  script_cve_id("CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3631", "CVE-2014-6410", "CVE-2014-6416", "CVE-2014-6417", "CVE-2014-6418");
  script_tag(name:"creation_date", value:"2014-10-10 04:10:10 +0000 (Fri, 10 Oct 2014)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2379-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2379-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2379-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2379-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steven Vittitoe reported multiple stack buffer overflows in Linux kernel's
magicmouse HID driver. A physically proximate attacker could exploit this
flaw to cause a denial of service (system crash) or possibly execute
arbitrary code via specially crafted devices. (CVE-2014-3181)

Ben Hawkes reported some off by one errors for report descriptors in the
Linux kernel's HID stack. A physically proximate attacker could exploit
these flaws to cause a denial of service (out-of-bounds write) via a
specially crafted device. (CVE-2014-3184)

Several bounds check flaws allowing for buffer overflows were discovered in
the Linux kernel's Whiteheat USB serial driver. A physically proximate
attacker could exploit these flaws to cause a denial of service (system
crash) via a specially crafted device. (CVE-2014-3185)

Steven Vittitoe reported a buffer overflow in the Linux kernel's PicoLCD
HID device driver. A physically proximate attacker could exploit this flaw
to cause a denial of service (system crash) or possibly execute arbitrary
code via a specially craft device. (CVE-2014-3186)

A flaw was discovered in the Linux kernel's associative-array garbage
collection implementation. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have other unspecified impact
by using keyctl operations. (CVE-2014-3631)

A flaw was discovered in the Linux kernel's UDF filesystem (used on some
CD-ROMs and DVDs) when processing indirect ICBs. An attacker who can cause
CD, DVD or image file with a specially crafted inode to be mounted can
cause a denial of service (infinite loop or stack consumption).
(CVE-2014-6410)

James Eckersall discovered a buffer overflow in the Ceph filesystem in the
Linux kernel. A remote attacker could exploit this flaw to cause a denial
of service (memory consumption and panic) or possibly have other
unspecified impact via a long unencrypted auth ticket. (CVE-2014-6416)

James Eckersall discovered a flaw in the handling of memory allocation
failures in the Ceph filesystem. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or possibly have unspecified
other impact. (CVE-2014-6417)

James Eckersall discovered a flaw in how the Ceph filesystem validates auth
replies. A remote attacker could exploit this flaw to cause a denial of
service (system crash) or possibly have other unspecified impact.
(CVE-2014-6418)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-generic-lpae", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-generic", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-lowlatency", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-powerpc-e500", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-powerpc-e500mc", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-powerpc-smp", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-powerpc64-emb", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-37-powerpc64-smp", ver:"3.13.0-37.64", rls:"UBUNTU14.04 LTS"))) {
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
