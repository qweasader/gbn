# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2031");
  script_cve_id("CVE-2019-12973", "CVE-2020-27842");
  script_tag(name:"creation_date", value:"2022-07-14 09:11:04 +0000 (Thu, 14 Jul 2022)");
  script_version("2022-07-14T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-14 10:10:42 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for openjpeg2 (EulerOS-SA-2022-2031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2031");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2031");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'openjpeg2' package(s) announced via the EulerOS-SA-2022-2031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There's a flaw in openjpeg's t2 encoder in versions prior to 2.4.0. An attacker who is able to provide crafted input to be processed by openjpeg could cause a null pointer dereference. The highest impact of this flaw is to application availability.(CVE-2020-27842)

In OpenJPEG 2.3.1, there is excessive iteration in the opj_t1_encode_cblks function of openjp2/t1.c. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted bmp file. This issue is similar to CVE-2018-6616.(CVE-2019-12973)");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.1~5.h6.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
