# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2381");
  script_cve_id("CVE-2013-4549", "CVE-2014-0190", "CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859", "CVE-2015-1860", "CVE-2018-15518", "CVE-2018-19871", "CVE-2018-19872");
  script_tag(name:"creation_date", value:"2020-01-23 12:52:29 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-28 21:03:27 +0000 (Mon, 28 Jan 2019)");

  script_name("Huawei EulerOS: Security Advisory for qt (EulerOS-SA-2019-2381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2381");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2381");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qt' package(s) announced via the EulerOS-SA-2019-2381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"QXmlSimpleReader in Qt before 5.2 allows context-dependent attackers to cause a denial of service (memory consumption) via an XML Entity Expansion (XEE) attack.(CVE-2013-4549)

An issue was discovered in Qt before 5.11.3. There is QTgaFile Uncontrolled Resource Consumption.(CVE-2018-19871)

QXmlStream in Qt 5.x before 5.11.3 has a double-free or corruption during parsing of a specially crafted illegal XML document.(CVE-2018-15518)

An issue was discovered in Qt 5.11. A malformed PPM image causes a division by zero and a crash in qppmhandler.cpp.(CVE-2018-19872)

Multiple buffer overflows in gui/image/qbmphandler.cpp in the QtBase module in Qt before 4.8.7 and 5.x before 5.4.2 allow remote attackers to cause a denial of service (segmentation fault and crash) and possibly execute arbitrary code via a crafted BMP image.(CVE-2015-1858)

Multiple buffer overflows in plugins/imageformats/ico/qicohandler.cpp in the QtBase module in Qt before 4.8.7 and 5.x before 5.4.2 allow remote attackers to cause a denial of service (segmentation fault and crash) and possibly execute arbitrary code via a crafted ICO image.(CVE-2015-1859)

Multiple buffer overflows in gui/image/qgifhandler.cpp in the QtBase module in Qt before 4.8.7 and 5.x before 5.4.2 allow remote attackers to cause a denial of service (segmentation fault) and possibly execute arbitrary code via a crafted GIF image.(CVE-2015-1860)

The BMP decoder in QtGui in QT before 5.5 does not properly calculate the masks used to extract the color components, which allows remote attackers to cause a denial of service (divide-by-zero and crash) via a crafted BMP file.(CVE-2015-0295)

The GIF decoder in QtGui in Qt before 5.3 allows remote attackers to cause a denial of service (NULL pointer dereference) via invalid width and height values in a GIF image.(CVE-2014-0190)");

  script_tag(name:"affected", value:"'qt' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"qt", rpm:"qt~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.8.5~12.h6", rls:"EULEROS-2.0SP2"))) {
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
