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
  script_oid("1.3.6.1.4.1.25623.1.0.123824");
  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327", "CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255", "CVE-2012-1820");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:49:18 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-1259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1259");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1259.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the ELSA-2012-1259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.99.15-7.2]
- improve fix for CVE-2011-3325

[0.99.15-7.1]
- fix CVE-2011-3323
- fix CVE-2011-3324
- fix CVE-2011-3325
- fix CVE-2011-3326
- fix CVE-2011-3327
- fix CVE-2012-0255
- fix CVE-2012-0249 and CVE-2012-0250
- fix CVE-2012-1820

[0.99.15-7]
- Resolves: #684751 - CVE-2010-1674 CVE-2010-1675 quagga various flaws

[0.99.15-6]
- Resolves: #644832 - CVE-2010-2948 CVE-2010-2949 quagga various flaws");

  script_tag(name:"affected", value:"'quagga' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.15~7.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.15~7.el6_3.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~0.99.15~7.el6_3.2", rls:"OracleLinux6"))) {
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
