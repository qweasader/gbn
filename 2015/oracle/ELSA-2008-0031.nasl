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
  script_oid("1.3.6.1.4.1.25623.1.0.122616");
  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:26 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0031");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the ELSA-2008-0031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.1.1-48.26.4.0.1]
 - Add Enterprise Linux detection

 [1.1.1-48.26.4]
 - cve-2007-5760.patch: XFree86-Misc Extension Invalid Array Index
 Vulnerability
 - cve-2007-5958.patch: Xorg / XFree86 file existence disclosure
 vulnerability
 - cve-2007-6427.patch: XInput Extension Memory Corruption Vulnerability
 - cve-2007-6428.patch: TOG-CUP Extension Memory Corruption Vulnerability
 - cve-2007-6429.patch: EVI and MIT-SHM Extension Integer Overflow
 Vulnerability");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.26.el5_1.4.0.1", rls:"OracleLinux5"))) {
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
