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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1230");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1125");
  script_tag(name:"creation_date", value:"2020-01-23 11:18:09 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-04-07T14:39:39+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:39:39 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 14:59:00 +0000 (Wed, 09 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for procps-ng (EulerOS-SA-2018-1230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1230");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1230");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'procps-ng' package(s) announced via the EulerOS-SA-2018-1230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If the HOME environment variable is unset or empty, top will read its configuration file from the current working directory without any security check. If a user runs top with HOME unset in an attacker-controlled directory, the attacker could achieve privilege escalation by exploiting one of several vulnerabilities in the config_file() function.(CVE-2018-1122)

Due to incorrect accounting when decoding and escaping Unicode data in procfs, ps is vulnerable to overflowing an mmap()ed region when formatting the process list for display. Since ps maps a guard page at the end of the buffer, impact is limited to a crash.(CVE-2018-1123)

If an argument longer than INT_MAX bytes is given to pgrep, 'int bytes' could wrap around back to a large positive int (rather than approaching zero), leading to a stack buffer overflow via strncat().(CVE-2018-1125)");

  script_tag(name:"affected", value:"'procps-ng' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"procps-ng", rpm:"procps-ng~3.3.10~17.2.h6", rls:"EULEROS-2.0SP3"))) {
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
