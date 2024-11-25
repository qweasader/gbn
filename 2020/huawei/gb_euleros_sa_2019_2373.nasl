# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2373");
  script_cve_id("CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7730");
  script_tag(name:"creation_date", value:"2020-01-23 12:51:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 14:09:26 +0000 (Tue, 27 Mar 2018)");

  script_name("Huawei EulerOS: Security Advisory for exempi (EulerOS-SA-2019-2373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2373");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2373");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'exempi' package(s) announced via the EulerOS-SA-2019-2373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Exempi before 2.4.4. Integer overflow in the Chunk class in XMPFiles/source/FormatSupport/RIFF.cpp allows remote attackers to cause a denial of service (infinite loop) via crafted XMP data in a .avi file.(CVE-2017-18233)

An issue was discovered in Exempi before 2.4.4. The ASF_Support::ReadHeaderObject function in XMPFiles/source/FormatSupport/ASF_Support.cpp allows remote attackers to cause a denial of service (infinite loop) via a crafted .asf file.(CVE-2017-18236)

An issue was discovered in Exempi before 2.4.4. The TradQT_Manager::ParseCachedBoxes function in XMPFiles/source/FormatSupport/QuickTime_Support.cpp allows remote attackers to cause a denial of service (infinite loop) via crafted XMP data in a .qt file.(CVE-2017-18238)

An issue was discovered in Exempi through 2.4.4. A certain case of a 0xffffffff length is mishandled in XMPFiles/source/FormatSupport/PSIR_FileWriter.cpp, leading to a heap-based buffer over-read in the PSD_MetaHandler::CacheFileData() function.(CVE-2018-7730)");

  script_tag(name:"affected", value:"'exempi' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"exempi", rpm:"exempi~2.2.0~8.h2", rls:"EULEROS-2.0SP2"))) {
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
