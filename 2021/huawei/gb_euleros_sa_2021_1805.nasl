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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1805");
  script_cve_id("CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2842", "CVE-2019-2945", "CVE-2019-2958", "CVE-2019-2962", "CVE-2019-2964", "CVE-2019-2973", "CVE-2019-2978", "CVE-2019-2981", "CVE-2019-2983", "CVE-2019-2988", "CVE-2019-2989", "CVE-2019-2992", "CVE-2019-2999");
  script_tag(name:"creation_date", value:"2021-05-03 06:20:58 +0000 (Mon, 03 May 2021)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 18:47:00 +0000 (Thu, 06 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for java-1.7.0-openjdk (EulerOS-SA-2021-1805)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1805");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1805");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'java-1.7.0-openjdk' package(s) announced via the EulerOS-SA-2021-1805 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking). Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13, Java SE Embedded: 8u221. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.(CVE-2019-2978)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13, Java SE Embedded: 8u221. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.(CVE-2019-2988)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking). Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13, Java SE Embedded: 8u221. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded accessible data.(CVE-2019-2989)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13, Java SE Embedded: 8u221. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.(CVE-2019-2992)

Vulnerability in the Java SE product of Oracle Java SE (component: Javadoc). Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized read access to a subset of Java SE accessible ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.191~2.6.15.4.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.191~2.6.15.4.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.191~2.6.15.4.h10", rls:"EULEROS-2.0SP3"))) {
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
