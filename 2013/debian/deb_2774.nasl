# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.702774");
  script_cve_id("CVE-2013-4351", "CVE-2013-4402");
  script_tag(name:"creation_date", value:"2013-10-09 22:00:00 +0000 (Wed, 09 Oct 2013)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2774)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2774");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2774");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2774");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg2' package(s) announced via the DSA-2774 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in GnuPG 2, the GNU privacy guard, a free PGP replacement. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-4351

When a key or subkey had its key flags subpacket set to all bits off, GnuPG currently would treat the key as having all bits set. That is, where the owner wanted to indicate no use permitted, GnuPG would interpret it as all use permitted. Such no use permitted keys are rare and only used in very special circumstances.

CVE-2013-4402

Infinite recursion in the compressed packet parser was possible with crafted input data, which may be used to cause a denial of service.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.0.14-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 2.0.19-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 2.0.22-1.

We recommend that you upgrade your gnupg2 packages.");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-agent", ver:"2.0.14-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.0.14-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgsm", ver:"2.0.14-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-agent", ver:"2.0.19-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.0.19-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgsm", ver:"2.0.19-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scdaemon", ver:"2.0.19-2+deb7u1", rls:"DEB7"))) {
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
