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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2635");
  script_cve_id("CVE-2017-2586", "CVE-2017-2587", "CVE-2017-5849", "CVE-2018-8975");
  script_tag(name:"creation_date", value:"2020-01-23 13:10:32 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-04-07T14:39:39+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:39:39 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 05:15:00 +0000 (Thu, 04 Feb 2021)");

  script_name("Huawei EulerOS: Security Advisory for netpbm (EulerOS-SA-2019-2635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2635");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2635");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'netpbm' package(s) announced via the EulerOS-SA-2019-2635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A memory allocation vulnerability was found in netpbm before 10.61. A maliciously crafted SVG file could cause the application to crash.(CVE-2017-2587)

A null pointer dereference vulnerability was found in netpbm before 10.61. A maliciously crafted SVG file could cause the application to crash.(CVE-2017-2586)

The pm_mallocarray2 function in lib/util/mallocvar.c in Netpbm through 10.81.03 allows remote attackers to cause a denial of service (heap-based buffer over-read) via a crafted image file, as demonstrated by pbmmask.(CVE-2018-8975)

tiffttopnm in netpbm 10.47.63 does not properly use the libtiff TIFFRGBAImageGet function, which allows remote attackers to cause a denial of service (out-of-bounds read and write) via a crafted tiff image file, related to transposing width and height values.(CVE-2017-5849)");

  script_tag(name:"affected", value:"'netpbm' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.61.02~9.h2", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.61.02~9.h2", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.61.02~9.h2", rls:"EULEROS-2.0SP3"))) {
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
