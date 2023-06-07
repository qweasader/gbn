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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1192");
  script_cve_id("CVE-2018-10911");
  script_tag(name:"creation_date", value:"2020-01-23 11:34:07 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-04-25T04:12:45+0000");
  script_tag(name:"last_modification", value:"2022-04-25 04:12:45 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 19:06:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for glusterfs (EulerOS-SA-2019-1192)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.4");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1192");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1192");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glusterfs' package(s) announced via the EulerOS-SA-2019-1192 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"glusterfs: Improper deserialization in dict.c:dict_unserialize() can allow attackers to read arbitrary memory (CVE-2018-10911)");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Huawei EulerOS Virtualization 2.5.4.");

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

if(release == "EULEROSVIRT-2.5.4") {

  if(!isnull(res = isrpmvuln(pkg:"glusterfs", rpm:"glusterfs~3.8.4~54.15.h1.eulerosv2r7", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-api", rpm:"glusterfs-api~3.8.4~54.15.h1.eulerosv2r7", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-cli", rpm:"glusterfs-cli~3.8.4~54.15.h1.eulerosv2r7", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-client-xlators", rpm:"glusterfs-client-xlators~3.8.4~54.15.h1.eulerosv2r7", rls:"EULEROSVIRT-2.5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-libs", rpm:"glusterfs-libs~3.8.4~54.15.h1.eulerosv2r7", rls:"EULEROSVIRT-2.5.4"))) {
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
