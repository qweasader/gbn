# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1187");
  script_cve_id("CVE-2005-1849", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9843", "CVE-2018-25032", "CVE-2022-37434");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 18:38:00 +0000 (Thu, 11 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for deltarpm (EulerOS-SA-2023-1187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1187");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1187");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'deltarpm' package(s) announced via the EulerOS-SA-2023-1187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches.(CVE-2018-25032)

zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).(CVE-2022-37434)

inftrees.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging improper pointer arithmetic.(CVE-2016-9840)

The crc32_big function in crc32.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact via vectors involving big-endian CRC calculation.(CVE-2016-9843)

inftrees.h in zlib 1.2.2 allows remote attackers to cause a denial of service (application crash) via an invalid file that causes a large dynamic tree to be produced.(CVE-2005-1849)

inffast.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging improper pointer arithmetic.(CVE-2016-9841)");

  script_tag(name:"affected", value:"'deltarpm' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"deltarpm", rpm:"deltarpm~3.6.2~2.h3.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
