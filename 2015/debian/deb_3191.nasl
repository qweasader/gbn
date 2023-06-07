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
  script_oid("1.3.6.1.4.1.25623.1.0.703191");
  script_cve_id("CVE-2015-0282", "CVE-2015-0294");
  script_tag(name:"creation_date", value:"2015-03-14 23:00:00 +0000 (Sat, 14 Mar 2015)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 15:24:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3191");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3191");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3191");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-3191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in GnuTLS, a library implementing the TLS and SSL protocols. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0282

GnuTLS does not verify the RSA PKCS #1 signature algorithm to match the signature algorithm in the certificate, leading to a potential downgrade to a disallowed algorithm without detecting it.

CVE-2015-0294

It was reported that GnuTLS does not check whether the two signature algorithms match on certificate import.

For the stable distribution (wheezy), these problems have been fixed in version 2.12.20-8+deb7u3.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.0.22-3+really2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"guile-gnutls", ver:"3.0.22-3+really2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8+deb7u3", rls:"DEB7"))) {
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
