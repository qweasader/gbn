# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703488");
  script_cve_id("CVE-2016-0739");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:45 +0000 (Tue, 08 Mar 2016)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)");

  script_name("Debian: Security Advisory (DSA-3488)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3488");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3488");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3488");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh' package(s) announced via the DSA-3488 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aris Adamantiadis discovered that libssh, a tiny C SSH library, incorrectly generated a short ephemeral secret for the diffie-hellman-group1 and diffie-hellman-group14 key exchange methods. The resulting secret is 128 bits long, instead of the recommended sizes of 1024 and 2048 bits respectively. This flaw could allow an eavesdropper with enough resources to decrypt or intercept SSH sessions.

For the oldstable distribution (wheezy), this problem has been fixed in version 0.5.4-1+deb7u3. This update also includes fixes for CVE-2014-8132 and CVE-2015-3146, which were previously scheduled for the next wheezy point release.

For the stable distribution (jessie), this problem has been fixed in version 0.6.3-4+deb8u2.

We recommend that you upgrade your libssh packages.");

  script_tag(name:"affected", value:"'libssh' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.5.4-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dbg", ver:"0.5.4-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dev", ver:"0.5.4-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-doc", ver:"0.5.4-1+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dbg", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dev", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-doc", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-gcrypt-4", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-gcrypt-dev", ver:"0.6.3-4+deb8u2", rls:"DEB8"))) {
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
