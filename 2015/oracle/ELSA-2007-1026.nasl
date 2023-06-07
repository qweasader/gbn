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
  script_oid("1.3.6.1.4.1.25623.1.0.122632");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:53 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2007-1026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-1026");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-1026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the ELSA-2007-1026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.3.27-8.1]
 Fixes for:
 - 345101 - CVE-2007-4352 xpdf memory corruption in DCTStream::readProgressiveDataUnit()
 - 345111 - CVE-2007-5392 xpdf buffer overflow in DCTStream::reset()
 - 345121 - CVE-2007-5393 xpdf buffer overflow in CCITTFaxStream::lookChar()");

  script_tag(name:"affected", value:"'poppler' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~4.3.el5_1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~4.3.el5_1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.5.4~4.3.el5_1", rls:"OracleLinux5"))) {
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