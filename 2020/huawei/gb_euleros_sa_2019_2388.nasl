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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2388");
  script_cve_id("CVE-2016-2145", "CVE-2016-2146", "CVE-2017-6807");
  script_tag(name:"creation_date", value:"2020-01-23 12:52:57 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-04-07T14:39:39+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:39:39 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-25 13:58:00 +0000 (Mon, 25 Apr 2016)");

  script_name("Huawei EulerOS: Security Advisory for mod_auth_mellon (EulerOS-SA-2019-2388)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2388");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2388");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mod_auth_mellon' package(s) announced via the EulerOS-SA-2019-2388 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mod_auth_mellon before 0.13.1 is vulnerable to a Cross-Site Session Transfer attack, where a user with access to one web site running on a server can copy their session cookie to a different web site on the same server to get access to that site.(CVE-2017-6807)

The am_read_post_data function in mod_auth_mellon before 0.11.1 does not check if the ap_get_client_block function returns an error, which allows remote attackers to cause a denial of service (segmentation fault and process crash) via a crafted POST data.(CVE-2016-2145)

The am_read_post_data function in mod_auth_mellon before 0.11.1 does not limit the amount of data read, which allows remote attackers to cause a denial of service (worker process crash, web server deadlock, or memory consumption) via a large amount of POST data.(CVE-2016-2146)");

  script_tag(name:"affected", value:"'mod_auth_mellon' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_mellon", rpm:"mod_auth_mellon~0.11.0~1.h4", rls:"EULEROS-2.0SP2"))) {
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
