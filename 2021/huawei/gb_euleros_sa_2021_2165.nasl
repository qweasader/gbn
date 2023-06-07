# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2165");
  script_cve_id("CVE-2019-1747", "CVE-2019-20477");
  script_tag(name:"creation_date", value:"2021-07-07 08:44:52 +0000 (Wed, 07 Jul 2021)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 13:21:00 +0000 (Thu, 28 May 2020)");

  script_name("Huawei EulerOS: Security Advisory for PyYAML (EulerOS-SA-2021-2165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2165");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'PyYAML' package(s) announced via the EulerOS-SA-2021-2165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the implementation of the Short Message Service (SMS) handling functionality of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to improper processing of SMS protocol data units (PDUs) that are encoded with a special character set. An attacker could exploit this vulnerability by sending a malicious SMS message to an affected device. A successful exploit could allow the attacker to cause the wireless WAN (WWAN) cellular interface module on an affected device to crash, resulting in a DoS condition that would require manual intervention to restore normal operating conditions. (CVE-2019-1747)

PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342. (CVE-2019-20477)");

  script_tag(name:"affected", value:"'PyYAML' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"PyYAML", rpm:"PyYAML~3.10~11.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
