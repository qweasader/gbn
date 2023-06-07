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
  script_oid("1.3.6.1.4.1.25623.1.0.702628");
  script_cve_id("CVE-2013-0288");
  script_tag(name:"creation_date", value:"2013-06-17 22:00:00 +0000 (Mon, 17 Jun 2013)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2628)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2628");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2628");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2628");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss-pam-ldapd' package(s) announced via the DSA-2628 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Garth Mollett discovered that a file descriptor overflow issue in the use of FD_SET() in nss-pam-ldapd, which provides NSS and PAM modules for using LDAP as a naming service, can lead to a stack-based buffer overflow. An attacker could, under some circumstances, use this flaw to cause a process that has the NSS or PAM module loaded to crash or potentially execute arbitrary code.

For the stable distribution (squeeze) this problem has been fixed in version 0.7.15+squeeze4.

For the testing distribution (wheezy), this problem has been fixed in version 0.8.10-3.

For the unstable distribution (sid), this problem has been fixed in version 0.8.10-3.

We recommend that you upgrade your nss-pam-ldapd packages.");

  script_tag(name:"affected", value:"'nss-pam-ldapd' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnss-ldapd", ver:"0.7.15+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-ldapd", ver:"0.7.15+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nslcd", ver:"0.7.15+squeeze3", rls:"DEB6"))) {
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
