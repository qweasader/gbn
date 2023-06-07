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
  script_oid("1.3.6.1.4.1.25623.1.0.704690");
  script_cve_id("CVE-2020-10957", "CVE-2020-10958", "CVE-2020-10967");
  script_tag(name:"creation_date", value:"2020-05-21 03:00:08 +0000 (Thu, 21 May 2020)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-13 22:15:00 +0000 (Tue, 13 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4690)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4690");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4690");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4690");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dovecot' package(s) announced via the DSA-4690 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Dovecot email server, which could cause crashes in the submission, submission-login or lmtp services, resulting in denial of service.

For the stable distribution (buster), these problems have been fixed in version 1:2.3.4.1-5+deb10u2.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dovecot' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-auth-lua", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-submissiond", ver:"1:2.3.4.1-5+deb10u2", rls:"DEB10"))) {
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
