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
  script_oid("1.3.6.1.4.1.25623.1.0.703184");
  script_cve_id("CVE-2014-3591", "CVE-2015-0837", "CVE-2015-1606");
  script_tag(name:"creation_date", value:"2015-03-11 23:00:00 +0000 (Wed, 11 Mar 2015)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-14 13:59:00 +0000 (Sat, 14 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3184");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3184");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3184");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-3184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in GnuPG, the GNU Privacy Guard:

CVE-2014-3591

The Elgamal decryption routine was susceptible to a side-channel attack discovered by researchers of Tel Aviv University. Ciphertext blinding was enabled to counteract it. Note that this may have a quite noticeable impact on Elgamal decryption performance.

CVE-2015-0837

The modular exponentiation routine mpi_powm() was susceptible to a side-channel attack caused by data-dependent timing variations when accessing its internal pre-computed table.

CVE-2015-1606

The keyring parsing code did not properly reject certain packet types not belonging in a keyring, which caused an access to memory already freed. This could allow remote attackers to cause a denial of service (crash) via crafted keyring files.

For the stable distribution (wheezy), these problems have been fixed in version 1.4.12-7+deb7u7.

For the upcoming stable distribution (jessie), these problems have been fixed in version 1.4.18-7.

For the unstable distribution (sid), these problems have been fixed in version 1.4.18-7.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-udeb", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-udeb", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv", ver:"1.4.12-7+deb7u7", rls:"DEB7"))) {
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
