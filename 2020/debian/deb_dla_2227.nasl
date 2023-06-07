# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892227");
  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_tag(name:"creation_date", value:"2020-05-31 03:00:16 +0000 (Sun, 31 May 2020)");
  script_version("2023-03-09T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:43 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2227");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2227");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DLA-2227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server implementation.

CVE-2020-8616

It was discovered that BIND does not sufficiently limit the number of fetches performed when processing referrals. An attacker can take advantage of this flaw to cause a denial of service (performance degradation) or use the recursing server in a reflection attack with a high amplification factor.

CVE-2020-8617

It was discovered that a logic error in the code which checks TSIG validity can be used to trigger an assertion failure, resulting in denial of service.

For Debian 8 Jessie, these problems have been fixed in version 1:9.9.5.dfsg-9+deb8u19.

We recommend that you upgrade your bind9 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"host", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-export-dev", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-90", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export100-udeb", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns-export100", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns100", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export91-udeb", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libirs-export91", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export95-udeb", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc-export95", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc95", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc90", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export90-udeb", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg-export90", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg90", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres90", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.9.5.dfsg-9+deb8u19", rls:"DEB8"))) {
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
