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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2685");
  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5977", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5981", "CVE-2018-16548", "CVE-2018-6381", "CVE-2018-6484", "CVE-2018-6540", "CVE-2018-6541", "CVE-2018-6869");
  script_tag(name:"creation_date", value:"2020-01-23 13:13:55 +0000 (Thu, 23 Jan 2020)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)");

  script_name("Huawei EulerOS: Security Advisory for zziplib (EulerOS-SA-2019-2685)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2685");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2685");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'zziplib' package(s) announced via the EulerOS-SA-2019-2685 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in ZZIPlib through 0.13.69. There is a memory leak triggered in the function __zzip_parse_root_directory in zip.c, which will lead to a denial of service attack.(CVE-2018-16548)

Heap-based buffer overflow in the __zzip_get32 function in fetch.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.(CVE-2017-5974)

Heap-based buffer overflow in the __zzip_get64 function in fetch.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.(CVE-2017-5975)

Heap-based buffer overflow in the zzip_mem_entry_extra_block function in memdisk.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.(CVE-2017-5976)

In ZZIPlib 0.13.67, there is a bus error caused by loading of a misaligned address (when handling disk64_trailer local entries) in __zzip_fetch_disk_trailer (zzip/zip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-6541)

In ZZIPlib 0.13.67, there is a bus error caused by loading of a misaligned address in the zzip_disk_findfirst function of zzip/mmapped.c. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-6540)

In ZZIPlib 0.13.67, there is a memory alignment error and bus error in the __zzip_fetch_disk_trailer function of zzip/zip.c. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-6484)

In ZZIPlib 0.13.67, there is a segmentation fault caused by invalid memory access in the zzip_disk_fread function (zzip/mmapped.c) because the size variable is not validated against the amount of file->stored data.(CVE-2018-6381)

In ZZIPlib 0.13.68, there is an uncontrolled memory allocation and a crash in the __zzip_parse_root_directory function of zzip/zip.c. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-6869)

seeko.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (assertion failure and crash) via a crafted ZIP file.(CVE-2017-5981)

The prescan_entry function in fseeko.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (NULL pointer dereference and crash) via a crafted ZIP file.(CVE-2017-5979)

The zzip_mem_entry_extra_block function in memdisk.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (invalid memory read and crash) via a crafted ZIP file.(CVE-2017-5977)

The zzip_mem_entry_new function in memdisk.c in zziplib 0.13.62 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted ZIP file.(CVE-2017-5978)");

  script_tag(name:"affected", value:"'zziplib' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"zziplib", rpm:"zziplib~0.13.62~9.h3", rls:"EULEROS-2.0SP3"))) {
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
