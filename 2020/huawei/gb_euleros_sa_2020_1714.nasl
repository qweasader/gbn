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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1714");
  script_cve_id("CVE-2017-15298");
  script_tag(name:"creation_date", value:"2020-07-03 06:18:30 +0000 (Fri, 03 Jul 2020)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)");

  script_name("Huawei EulerOS: Security Advisory for git (EulerOS-SA-2020-1714)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1714");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1714");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2020-1714 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Git through 2.14.2 mishandles layers of tree objects, which allows remote attackers to cause a denial of service (memory consumption) via a crafted repository, aka a Git bomb. This can also have an impact of disk consumption, however, an affected process typically would not survive its attempt to build the data structure in memory before writing to disk.(CVE-2017-15298)");

  script_tag(name:"affected", value:"'git' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~1.8.3.1~20.h2", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~1.8.3.1~20.h2", rls:"EULEROSVIRT-3.0.6.0"))) {
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
