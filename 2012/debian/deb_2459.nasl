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
  script_oid("1.3.6.1.4.1.25623.1.0.71342");
  script_cve_id("CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255");
  script_tag(name:"creation_date", value:"2012-05-31 15:42:51 +0000 (Thu, 31 May 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2459)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2459");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2459");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2459");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-2459 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Quagga, a routing daemon.

CVE-2012-0249

A buffer overflow in the ospf_ls_upd_list_lsa function in the OSPFv2 implementation allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a Link State Update (aka LS Update) packet that is smaller than the length specified in its header.

CVE-2012-0250

A buffer overflow in the OSPFv2 implementation allows remote attackers to cause a denial of service (daemon crash) via a Link State Update (aka LS Update) packet containing a network-LSA link-state advertisement for which the data-structure length is smaller than the value in the Length header field.

CVE-2012-0255

The BGP implementation does not properly use message buffers for OPEN messages, which allows remote attackers impersonating a configured BGP peer to cause a denial of service (assertion failure and daemon exit) via a message associated with a malformed AS4 capability.

This security update upgrades the quagga package to the most recent upstream release. This release includes other corrections, such as hardening against unknown BGP path attributes.

For the stable distribution (squeeze), these problems have been fixed in version 0.99.20.1-0+squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 0.99.20.1-1.

We recommend that you upgrade your quagga packages.");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"quagga-dbg", ver:"0.99.20.1-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.20.1-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.20.1-0+squeeze1", rls:"DEB6"))) {
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
