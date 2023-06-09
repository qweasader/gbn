# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.72171");
  script_cve_id("CVE-2012-2652", "CVE-2012-3515");
  script_tag(name:"creation_date", value:"2012-09-15 08:23:58 +0000 (Sat, 15 Sep 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2542)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2542");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2542");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2542");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu-kvm' package(s) announced via the DSA-2542 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in KVM, a full virtualization solution on x86 hardware. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-2652: The snapshot mode of QEMU (-snapshot) incorrectly handles temporary files used to store the current state, making it vulnerable to symlink attacks (including arbitrary file overwriting and guest information disclosure) due to a race condition.

CVE-2012-3515: QEMU does not properly handle VT100 escape sequences when emulating certain devices with a virtual console backend. An attacker within a guest with access to the vulnerable virtual console could overwrite memory of QEMU and escalate privileges to that of the qemu process.

For the stable distribution (squeeze), these problems have been fixed in version 0.12.5+dfsg-5+squeeze9.

For the testing distribution (wheezy), and the unstable distribution (sid), these problems will been fixed soon.

We recommend that you upgrade your qemu-kvm packages.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"1:0.12.5+dfsg-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm-dbg", ver:"0.12.5+dfsg-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.5+dfsg-5+squeeze9", rls:"DEB6"))) {
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
