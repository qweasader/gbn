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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1489");
  script_cve_id("CVE-2017-15232", "CVE-2019-2201");
  script_tag(name:"creation_date", value:"2021-03-05 07:08:28 +0000 (Fri, 05 Mar 2021)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-19 01:15:00 +0000 (Tue, 19 Nov 2019)");

  script_name("Huawei EulerOS: Security Advisory for libjpeg-turbo (EulerOS-SA-2021-1489)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1489");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1489");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libjpeg-turbo' package(s) announced via the EulerOS-SA-2021-1489 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In generate_jsimd_ycc_rgb_convert_neon of jsimd_arm64_neon.S, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution in an unprivileged process with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-120551338(CVE-2019-2201)

libjpeg-turbo 1.5.2 has a NULL Pointer Dereference in jdpostct.c and jquant1.c via a crafted JPEG file.(CVE-2017-15232)");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo", rpm:"libjpeg-turbo~1.2.90~6.h9.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-devel", rpm:"libjpeg-turbo-devel~1.2.90~6.h9.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
