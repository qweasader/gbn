# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704018");
  script_cve_id("CVE-2017-3735");
  script_tag(name:"creation_date", value:"2017-11-03 23:00:00 +0000 (Fri, 03 Nov 2017)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4018");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4018");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4018");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170828.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171102.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-4018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-3735

It was discovered that OpenSSL is prone to a one-byte buffer overread while parsing a malformed IPAddressFamily extension in an X.509 certificate.

Details can be found in the upstream advisory: [link moved to references]

CVE-2017-3736

It was discovered that OpenSSL contains a carry propagation bug in the x86_64 Montgomery squaring procedure.

Details can be found in the upstream advisory: [link moved to references]

For the oldstable distribution (jessie), CVE-2017-3735 has been fixed in version 1.0.1t-1+deb8u7. The oldstable distribution is not affected by CVE-2017-3736.

For the stable distribution (stretch), these problems have been fixed in version 1.1.0f-3+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 1.1.0g-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1t-1+deb8u7", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.1-udeb", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1-udeb", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.0f-3+deb9u1", rls:"DEB9"))) {
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
