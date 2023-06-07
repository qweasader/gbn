# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703143");
  script_cve_id("CVE-2015-0377", "CVE-2015-0418");
  script_tag(name:"creation_date", value:"2015-01-27 23:00:00 +0000 (Tue, 27 Jan 2015)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3143");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3143");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3143");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox' package(s) announced via the DSA-3143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in VirtualBox, a x86 virtualisation solution, which might result in denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 4.1.18-dfsg-2+deb7u4.

For the unstable distribution (sid), these problems have been fixed in version 4.3.18-dfsg-2.

We recommend that you upgrade your virtualbox packages.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-fuse", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-dbg", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-dkms", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-fuse", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-dkms", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-source", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-utils", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-guest-x11", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-qt", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose-source", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-ose", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox", ver:"4.1.18-dfsg-2+deb7u4", rls:"DEB7"))) {
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
