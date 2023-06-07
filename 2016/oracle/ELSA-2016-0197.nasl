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
  script_oid("1.3.6.1.4.1.25623.1.0.122876");
  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:19 +0000 (Thu, 18 Feb 2016)");
  script_version("2021-10-14T11:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-14 11:01:30 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Oracle: Security Advisory (ELSA-2016-0197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0197");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0197.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the ELSA-2016-0197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[38.6.1-1.0.1]
- Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat file

[38.6.1-1]
- Update to 38.6.1 ESR");

  script_tag(name:"affected", value:"'firefox' package(s) on Oracle Linux 5, Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.6.1~1.0.1.el5_11", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.6.1~1.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.6.1~1.0.1.el7_2", rls:"OracleLinux7"))) {
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
