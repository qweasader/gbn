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
  script_oid("1.3.6.1.4.1.25623.1.0.704697");
  script_cve_id("CVE-2020-13777");
  script_tag(name:"creation_date", value:"2020-06-07 03:00:04 +0000 (Sun, 07 Jun 2020)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4697)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4697");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4697");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4697");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gnutls28");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls28' package(s) announced via the DSA-4697 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was reported in the TLS session ticket key construction in GnuTLS, a library implementing the TLS and SSL protocols. The flaw caused the TLS server to not securely construct a session ticket encryption key considering the application supplied secret, allowing a man-in-the-middle attacker to bypass authentication in TLS 1.3 and recover previous conversations in TLS 1.2.

For the stable distribution (buster), this problem has been fixed in version 3.6.7-4+deb10u4.

We recommend that you upgrade your gnutls28 packages.

For the detailed security status of gnutls28 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-doc", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-dane0", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls28-dev", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutlsxx28", ver:"3.6.7-4+deb10u4", rls:"DEB10"))) {
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
