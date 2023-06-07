# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.64746");
  script_cve_id("CVE-2009-0668", "CVE-2009-0669");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1863)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1863");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1863");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1863");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zope2.9, zope2.10' package(s) announced via the DSA-1863 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the zope, a feature-rich web application server written in python, that could lead to arbitrary code execution in the worst case. The Common Vulnerabilities and Exposures project identified the following problems:

CVE-2009-0668

Due to a programming error an authorization method in the StorageServer component of ZEO was not used as an internal method. This allows a malicious client to bypass authentication when connecting to a ZEO server by simply calling this authorization method.

CVE-2009-0668

The ZEO server doesn't restrict the callables when unpickling data received from a malicious client which can be used by an attacker to execute arbitrary python code on the server by sending certain exception pickles. This also allows an attacker to import any importable module as ZEO is importing the module containing a callable specified in a pickle to test for a certain flag.

The update also limits the number of new object ids a client can request to 100 as it would be possible to consume huge amounts of resources by requesting a big batch of new object ids. No CVE id has been assigned to this.

The oldstable distribution (etch), this problem has been fixed in version 2.9.6-4etch2 of zope2.9.

For the stable distribution (lenny), this problem has been fixed in version 2.10.6-1+lenny1 of zope2.10.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.10.9-1 of zope2.10.

We recommend that you upgrade your zope2.10/zope2.9 packages.");

  script_tag(name:"affected", value:"'zope2.9, zope2.10' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"zope2.9-sandbox", ver:"2.9.6-4etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zope2.9", ver:"2.9.6-4etch2", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"zope2.10-sandbox", ver:"2.10.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zope2.10", ver:"2.10.6-1+lenny1", rls:"DEB5"))) {
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
