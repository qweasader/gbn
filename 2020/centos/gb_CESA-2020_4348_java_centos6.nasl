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
  script_oid("1.3.6.1.4.1.25623.1.0.883283");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14803");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 21:42:00 +0000 (Wed, 24 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-11-10 04:01:15 +0000 (Tue, 10 Nov 2020)");
  script_name("CentOS: Security Advisory for java (CESA-2020:4348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2020:4348");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-November/035810.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the CESA-2020:4348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Credentials sent over unencrypted LDAP connection (JNDI,
8237990) (CVE-2020-14781)

  * OpenJDK: Certificate blacklist bypass via alternate certificate encodings
(Libraries, 8237995) (CVE-2020-14782)

  * OpenJDK: Integer overflow leading to out-of-bounds access (Hotspot,
8241114) (CVE-2020-14792)

  * OpenJDK: Incomplete check for invalid characters in URI to path
conversion (Libraries, 8242685) (CVE-2020-14797)

  * OpenJDK: Race condition in NIO Buffer boundary checks (Libraries,
8244136) (CVE-2020-14803)

  * OpenJDK: High memory usage during deserialization of Proxy class with
many interfaces (Serialization, 8236862) (CVE-2020-14779)

  * OpenJDK: Missing permission check in path to URI conversion (Libraries,
8242680) (CVE-2020-14796)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'java' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-debug", rpm:"java-1.8.0-openjdk-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debug", rpm:"java-1.8.0-openjdk-demo-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debug", rpm:"java-1.8.0-openjdk-devel-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debug", rpm:"java-1.8.0-openjdk-headless-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-debug", rpm:"java-1.8.0-openjdk-javadoc-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-debug", rpm:"java-1.8.0-openjdk-src-debug~1.8.0.272.b10~0.el6_10", rls:"CentOS6"))) {
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
