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
  script_oid("1.3.6.1.4.1.25623.1.0.123419");
  script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:26:00 +0000 (Fri, 07 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-0449)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0449");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0449.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the ELSA-2014-0449 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[24.5.0-1.0.1]
- Replaced thunderbird-redhat-default-prefs.js with thunderbird-oracle-default-prefs.js

[24.5.0-1]
- Update to 24.5.0");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~24.5.0~1.0.1.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~24.5.0~1.0.1.el6_5", rls:"OracleLinux6"))) {
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
