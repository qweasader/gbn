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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1023");
  script_cve_id("CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8388", "CVE-2015-8391", "CVE-2016-3191");
  script_tag(name:"creation_date", value:"2020-01-23 10:38:33 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-07-22T10:11:18+0000");
  script_tag(name:"last_modification", value:"2022-07-22 10:11:18 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 17:29:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for pcre (EulerOS-SA-2016-1023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1023");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1023");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'pcre' package(s) announced via the EulerOS-SA-2016-1023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in the way PCRE handled malformed regular expressions. An attacker able to make an application using PCRE process a specially crafted regular expression could use these flaws to cause the application to crash or, possibly, execute arbitrary code. (CVE-2015-8385, CVE-2016-3191, CVE-2015-2328, CVE-2015-3217, CVE-2015-5073, CVE-2015-8388, CVE-2015-8391, CVE-2015-8386)");

  script_tag(name:"affected", value:"'pcre' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.32~15.1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.32~15.1", rls:"EULEROS-2.0SP1"))) {
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
