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
  script_oid("1.3.6.1.4.1.25623.1.0.131275");
  script_cve_id("CVE-2016-3119");
  script_tag(name:"creation_date", value:"2016-03-31 05:05:00 +0000 (Thu, 31 Mar 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0123");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0123.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18058");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/krb5-1.12/krb5-1.12.5.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179220.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the MGASA-2016-0123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that in all versions of MIT krb5, an authenticated
attacker with permission to modify a principal entry can cause kadmind to
dereference a null pointer by supplying an empty DB argument to the
modify_principal command, if kadmind is configured to use the LDAP KDB
module (CVE-2016-3119).

The krb5 package has been updated to version 1.12.5 and patched to fix
this issue and other bugs.");

  script_tag(name:"affected", value:"'krb5' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.12.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.12.5~1.mga5", rls:"MAGEIA5"))) {
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
